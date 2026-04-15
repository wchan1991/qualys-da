"""
Qualys API Client

Dual-auth client supporting:
- VM APIs (Basic auth via session login) — XML responses
- CSAM API (Bearer token via gateway auth) — JSON responses

Includes rate limiting, pagination, retry, and XML/JSON parsing.
"""

import time
import logging
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config_loader import QualysDAConfig

logger = logging.getLogger(__name__)


class QualysError(Exception):
    """Base exception for Qualys API errors."""
    def __init__(self, message: str, status_code: int = None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class AuthError(QualysError):
    """Authentication failed."""
    pass


class RateLimitError(QualysError):
    """Rate limit exceeded."""
    pass


@dataclass
class RateLimiter:
    """Token bucket rate limiter. Thread-safe: `acquire()` is guarded by a lock
    so parallel VM + CSAM fetches cannot race on `_tokens` / `_last_update`."""
    calls_per_minute: int
    burst_limit: int = 10
    _tokens: float = None
    _last_update: float = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        self._tokens = float(self.burst_limit)
        self._last_update = time.time()

    def acquire(self) -> float:
        """Acquire a token, blocking if the bucket is empty.

        Thread-safe: the critical section (refill + reserve) runs under the
        lock, but the sleep happens *after* releasing the lock so parallel
        callers don't serialize on each other's wait — they each reserve a
        future slot (by advancing `_last_update`) and then sleep in parallel.
        """
        with self._lock:
            now = time.time()
            elapsed = now - self._last_update
            refill_rate = self.calls_per_minute / 60.0
            self._tokens = min(self.burst_limit, self._tokens + elapsed * refill_rate)
            self._last_update = now
            if self._tokens >= 1:
                self._tokens -= 1
                return 0.0
            wait_time = (1 - self._tokens) / refill_rate
            self._tokens = 0
            # Reserve this caller's future slot so the next acquirer sees the
            # bucket as "empty until after our wait" — prevents thundering herd.
            self._last_update = now + wait_time
        time.sleep(wait_time)
        return wait_time


class QualysClient:
    """
    Qualys API client with dual auth for VM and CSAM platforms.

    Usage:
        with QualysClient(config) as client:
            hosts = client.fetch_vm_hosts()
            detections = client.fetch_vm_detections()
            assets = client.fetch_csam_assets()
    """

    def __init__(self, config: QualysDAConfig):
        self.config = config
        self._vm_session: Optional[requests.Session] = None
        self._csam_session: Optional[requests.Session] = None
        self._vm_authenticated = False
        self._vm_auth_expires: Optional[datetime] = None
        self._csam_token: Optional[str] = None
        self._csam_token_expires: Optional[datetime] = None

        self._rate_limiter = None
        if config.rate_limit_enabled:
            self._rate_limiter = RateLimiter(calls_per_minute=config.calls_per_minute)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        if self._vm_session:
            try:
                self._vm_session.post(
                    f"{self.config.vm_base_url}/api/2.0/fo/session/",
                    data={"action": "logout"},
                    timeout=10,
                )
            except Exception:
                pass
            self._vm_session.close()
            self._vm_session = None
        if self._csam_session:
            self._csam_session.close()
            self._csam_session = None

    # ── VM Session (Basic Auth) ──────────────────────────────────

    def _get_vm_session(self) -> requests.Session:
        if self._vm_session is None:
            self._vm_session = requests.Session()
            retry = Retry(
                total=self.config.max_retries,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry)
            self._vm_session.mount("https://", adapter)
            self._vm_session.headers.update({
                "X-Requested-With": "QualysDataAnalytics",
                "Accept": "application/xml",
            })
        return self._vm_session

    def _vm_authenticate(self) -> None:
        if self._vm_authenticated and self._vm_auth_expires:
            if datetime.now() < self._vm_auth_expires:
                return

        logger.info("Authenticating with Qualys VM API...")
        session = self._get_vm_session()
        url = f"{self.config.vm_base_url}/api/2.0/fo/session/"

        try:
            response = session.post(
                url,
                data={
                    "action": "login",
                    "username": self.config.username,
                    "password": self.config.password,
                },
                timeout=self.config.timeout,
            )
            if response.status_code == 200 and "logged in" in response.text.lower():
                self._vm_authenticated = True
                self._vm_auth_expires = datetime.now() + timedelta(hours=4)
                logger.info("VM authentication successful")
            else:
                raise AuthError(
                    f"VM authentication failed: {self._parse_xml_error(response.text)}"
                )
        except requests.RequestException as e:
            raise AuthError(f"VM authentication request failed: {e}")

    def _vm_request(self, method: str, endpoint: str, params: Dict = None,
                    data: Dict = None, timeout: int = None) -> requests.Response:
        if self._rate_limiter:
            self._rate_limiter.acquire()

        self._vm_authenticate()
        session = self._get_vm_session()
        url = f"{self.config.vm_base_url}{endpoint}"

        try:
            response = session.request(
                method=method, url=url, params=params, data=data,
                timeout=timeout or self.config.timeout,
            )
            if response.status_code == 401:
                self._vm_authenticated = False
                self._vm_authenticate()
                response = session.request(
                    method=method, url=url, params=params, data=data,
                    timeout=timeout or self.config.timeout,
                )
            if response.status_code == 429:
                raise RateLimitError("VM API rate limit exceeded")
            if response.status_code >= 500:
                raise QualysError(
                    f"VM API server error: {response.status_code}",
                    status_code=response.status_code,
                )
            return response
        except requests.RequestException as e:
            raise QualysError(f"VM API request failed: {e}")

    # ── CSAM Session (Bearer Token) ──────────────────────────────

    def _get_csam_session(self) -> requests.Session:
        if self._csam_session is None:
            self._csam_session = requests.Session()
            retry = Retry(
                total=self.config.max_retries,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry)
            self._csam_session.mount("https://", adapter)
            self._csam_session.headers.update({
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
        return self._csam_session

    def _csam_authenticate(self) -> None:
        """Authenticate with the Qualys Gateway and obtain a JWT.

        Qualys Gateway auth (`POST /auth`) is **form-encoded** and returns the
        JWT as a **plain-text** response body — not JSON. Sending a JSON body
        with `Content-Type: application/json` causes the gateway to return
        HTTP 500. The required form fields are `username`, `password`, and
        `token=true` (some platforms also accept `permissions=true`).

        Reference: Qualys Platform API — Gateway Service authentication.
        """
        if self._csam_token and self._csam_token_expires:
            if datetime.now() < self._csam_token_expires:
                return

        logger.info("Authenticating with Qualys CSAM API...")
        session = self._get_csam_session()
        url = f"{self.config.csam_base_url}/auth"

        try:
            # Override the session's default JSON Content-Type for this one call;
            # the gateway requires form encoding. `data=` makes requests set
            # `Content-Type: application/x-www-form-urlencoded` automatically.
            response = session.post(
                url,
                data={
                    "username": self.config.username,
                    "password": self.config.password,
                    "token": "true",
                    "permissions": "true",
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/plain",
                },
                timeout=self.config.timeout,
            )
            if response.status_code == 201 or response.status_code == 200:
                # Gateway returns the raw JWT in the response body (plain text).
                token = (response.text or "").strip()
                if not token:
                    # Fallback for older platforms that return JSON
                    try:
                        data = response.json()
                        token = data.get("token") or data.get("access_token") or ""
                    except ValueError:
                        token = ""
                if not token:
                    # Last-ditch: some deployments send the token in a header
                    token = response.headers.get("Authorization", "").replace("Bearer ", "").strip()
                if not token:
                    raise AuthError("CSAM auth: empty token in response body")

                self._csam_token = token
                self._csam_token_expires = datetime.now() + timedelta(hours=4)
                session.headers["Authorization"] = f"Bearer {self._csam_token}"
                logger.info("CSAM authentication successful")
            else:
                # Surface the response body so the failure can be diagnosed —
                # a bare HTTP code rarely tells you why the gateway rejected you.
                body = (response.text or "")[:400].replace("\n", " ")
                raise AuthError(
                    f"CSAM authentication failed: HTTP {response.status_code} "
                    f"(url={url}) body={body!r}"
                )
        except requests.RequestException as e:
            raise AuthError(f"CSAM authentication request failed: {e}")

    def _csam_apply_server_throttle(self, response: requests.Response) -> None:
        """Honour Qualys CSAM's own rate-limit / concurrency headers.

        When pulling large tenants (e.g. ~104k assets → ~100+ pages), the
        shared client-side token bucket is not enough — Qualys enforces its
        own per-API-key budget and a concurrency cap, and reports both via
        response headers on every CSAM call:

            X-RateLimit-Limit           per-window call budget
            X-RateLimit-Remaining       calls left in the current window
            X-RateLimit-ToWait-Sec      seconds until the window resets (if 0/low)
            X-Concurrency-Limit-Limit   max concurrent requests
            X-Concurrency-Limit-Running current concurrent requests

        Strategy: if Remaining is low OR ToWait-Sec is positive, sleep for
        the server-reported wait. If concurrency is saturated, back off for
        a small fixed window. This keeps big CSAM pulls from tripping 429s
        mid-pagination.
        """
        def _int_header(name):
            try:
                v = response.headers.get(name)
                return int(v) if v is not None and v.strip() != "" else None
            except (ValueError, AttributeError):
                return None

        remaining = _int_header("X-RateLimit-Remaining")
        to_wait = _int_header("X-RateLimit-ToWait-Sec")
        conc_limit = _int_header("X-Concurrency-Limit-Limit")
        conc_running = _int_header("X-Concurrency-Limit-Running")

        sleep_for = 0.0
        reason = None

        # Qualys returns ToWait-Sec > 0 when we're throttled *right now*.
        if to_wait is not None and to_wait > 0:
            sleep_for = float(to_wait)
            reason = f"server asked us to wait {to_wait}s (X-RateLimit-ToWait-Sec)"
        # If we're within 2 calls of the budget, burn a small delay so the
        # next page doesn't push us over.
        elif remaining is not None and remaining <= 2:
            sleep_for = 2.0
            reason = f"rate budget almost exhausted (Remaining={remaining})"
        # Concurrency saturated: brief pause lets in-flight calls drain.
        elif (conc_limit is not None and conc_running is not None
              and conc_running >= conc_limit):
            sleep_for = 1.0
            reason = (f"concurrency saturated "
                      f"({conc_running}/{conc_limit} in flight)")

        if sleep_for > 0:
            logger.info(f"CSAM throttle: sleeping {sleep_for:.1f}s — {reason}")
            time.sleep(sleep_for)

    def _csam_request(self, method: str, endpoint: str,
                      json_body: Any = None, params: Dict = None,
                      timeout: int = None) -> requests.Response:
        if self._rate_limiter:
            self._rate_limiter.acquire()

        self._csam_authenticate()
        session = self._get_csam_session()
        url = f"{self.config.csam_base_url}{endpoint}"

        try:
            response = session.request(
                method=method, url=url, json=json_body, params=params,
                timeout=timeout or self.config.timeout,
            )
            if response.status_code == 401:
                self._csam_token = None
                self._csam_authenticate()
                response = session.request(
                    method=method, url=url, json=json_body, params=params,
                    timeout=timeout or self.config.timeout,
                )
            # Honour Qualys CSAM rate-limit / concurrency headers before the
            # next call goes out. This is the big 104k-asset fix — without
            # it a parallel refresh can burn through the per-key budget and
            # start collecting 429s half-way through pagination.
            if 200 <= response.status_code < 300:
                self._csam_apply_server_throttle(response)
            if response.status_code == 429:
                # Server explicitly said stop. Honour Retry-After (RFC 7231)
                # or Qualys's own X-RateLimit-ToWait-Sec, then retry once.
                retry_after = response.headers.get("Retry-After")
                wait_hdr = response.headers.get("X-RateLimit-ToWait-Sec")
                try:
                    sleep_for = float(retry_after or wait_hdr or 30)
                except (TypeError, ValueError):
                    sleep_for = 30.0
                sleep_for = max(1.0, min(sleep_for, 120.0))  # clamp
                logger.warning(
                    f"CSAM 429 — sleeping {sleep_for:.0f}s then retrying once "
                    f"(Retry-After={retry_after!r}, "
                    f"X-RateLimit-ToWait-Sec={wait_hdr!r})"
                )
                time.sleep(sleep_for)
                response = session.request(
                    method=method, url=url, json=json_body, params=params,
                    timeout=timeout or self.config.timeout,
                )
                if response.status_code == 429:
                    raise RateLimitError(
                        "CSAM API rate limit exceeded — still 429 after retry"
                    )
                if 200 <= response.status_code < 300:
                    self._csam_apply_server_throttle(response)
            if response.status_code >= 500:
                raise QualysError(
                    f"CSAM API server error: {response.status_code}",
                    status_code=response.status_code,
                )
            return response
        except requests.RequestException as e:
            raise QualysError(f"CSAM API request failed: {e}")

    # ── Health Check ─────────────────────────────────────────────

    def health_check(self) -> Dict[str, Any]:
        result = {"vm": False, "csam": False, "vm_error": None, "csam_error": None}
        try:
            self._vm_authenticate()
            result["vm"] = True
        except (QualysError, Exception) as e:
            result["vm_error"] = str(e)
        try:
            self._csam_authenticate()
            result["csam"] = True
        except (QualysError, Exception) as e:
            result["csam_error"] = str(e)
        return result

    # ── Preflight Auth ───────────────────────────────────────────

    def ensure_authenticated(self) -> None:
        """Eagerly authenticate to both APIs. Raises AuthError if either fails.

        Call this at the start of a refresh so credential / connectivity
        problems surface in ~1–2 seconds instead of deep inside a partial pull
        (after CSAM/VM have already written thousands of rows to the DB).

        Both `_vm_authenticate()` and `_csam_authenticate()` no-op when a
        valid token/session is still cached, so calling this at the top of
        every refresh is cheap after the first run.
        """
        logger.info("Preflight: verifying Qualys auth (VM + CSAM)...")
        self._vm_authenticate()      # raises AuthError on failure
        self._csam_authenticate()    # raises AuthError on failure
        logger.info("Preflight OK — VM and CSAM both authenticated")

    # ── Expected-Count Preflight Helpers ─────────────────────────

    def count_vm_hosts(self) -> Optional[int]:
        """POST /api/3.0/fo/asset/host/?action=count — returns a single TOTAL.
        Returns None (non-fatal) if the count endpoint is unavailable."""
        try:
            resp = self._vm_request(
                "POST",
                "/api/3.0/fo/asset/host/",
                data={"action": "count"},
                timeout=30,
            )
            root = ET.fromstring(resp.text)
            # Qualys returns the figure in one of these elements depending on
            # platform / API revision.
            for tag in ("TOTAL", "COUNT", "TOTAL_HOSTS"):
                val = root.findtext(f".//{tag}")
                if val and val.strip().isdigit():
                    return int(val.strip())
            return None
        except Exception as e:
            logger.warning(f"VM host count preflight failed (non-fatal): {e}")
            return None

    def count_vm_detections(self) -> Optional[int]:
        """POST /api/5.0/fo/asset/host/vm/detection/?action=count.
        Returns None (non-fatal) on error."""
        try:
            resp = self._vm_request(
                "POST",
                "/api/5.0/fo/asset/host/vm/detection/",
                data={"action": "count"},
                timeout=60,
            )
            root = ET.fromstring(resp.text)
            for tag in ("TOTAL_HOST_DETECTIONS", "TOTAL_DETECTIONS", "TOTAL", "COUNT"):
                val = root.findtext(f".//{tag}")
                if val and val.strip().isdigit():
                    return int(val.strip())
            return None
        except Exception as e:
            logger.warning(f"VM detection count preflight failed (non-fatal): {e}")
            return None

    def count_csam_assets(self) -> Optional[int]:
        """POST /rest/2.0/count/am/asset — returns a single count field.
        Returns None (non-fatal) on error."""
        try:
            resp = self._csam_request(
                "POST",
                "/rest/2.0/count/am/asset",
                json_body={},
                timeout=30,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            rd = data.get("ServiceResponse", data)
            for key in ("count", "totalRecords", "total"):
                val = rd.get(key)
                if val is not None:
                    try:
                        return int(val)
                    except (TypeError, ValueError):
                        continue
            return None
        except Exception as e:
            logger.warning(f"CSAM count preflight failed (non-fatal): {e}")
            return None

    # ── XML Parsing Helpers ──────────────────────────────────────

    def _parse_xml_error(self, xml_text: str) -> str:
        try:
            root = ET.fromstring(xml_text)
            for tag in ["TEXT", "MESSAGE", "ERROR"]:
                elem = root.find(f".//{tag}")
                if elem is not None and elem.text:
                    return elem.text
        except ET.ParseError:
            pass
        return xml_text[:200]

    def _get_xml_text(self, elem, tag: str, default: str = "") -> str:
        child = elem.find(tag)
        return child.text.strip() if child is not None and child.text else default

    def _get_xml_int(self, elem, tag: str, default: int = 0) -> int:
        text = self._get_xml_text(elem, tag, "")
        try:
            return int(text) if text else default
        except ValueError:
            return default

    def _get_pagination_url(self, xml_text: str) -> Optional[str]:
        """Extract next-page URL from VM API WARNING element."""
        try:
            root = ET.fromstring(xml_text)
            warning = root.find(".//WARNING")
            if warning is not None:
                url_elem = warning.find("URL")
                if url_elem is not None and url_elem.text:
                    return url_elem.text.strip()
        except ET.ParseError:
            pass
        return None

    # ── Fetch VM Hosts ───────────────────────────────────────────

    def fetch_vm_hosts(self, max_pages: int = 500,
                       expected: Optional[int] = None) -> List[Dict]:
        """Fetch all hosts from VM Host List API v3.

        If `expected` is given (from count_vm_hosts()), logs it upfront and
        warns if the fetched total drifts (catches silent truncation on
        max_pages, rate-limit 429s, partial pagination, etc.)."""
        if expected is not None:
            logger.info(f"Fetching VM hosts... (expected: {expected:,})")
        else:
            logger.info("Fetching VM hosts...")
        all_hosts = []
        page = 0

        response = self._vm_request(
            "POST",
            "/api/3.0/fo/asset/host/",
            data={
                "action": "list",
                "details": "All/AGs",
                "truncation_limit": 1000,
                "show_tags": 1,
                "show_trurisk": 1,
            },
            timeout=120,
        )

        while page < max_pages:
            page += 1
            hosts = self._parse_vm_hosts_xml(response.text)
            all_hosts.extend(hosts)

            if page % 10 == 0:
                if expected:
                    logger.info(
                        f"  VM hosts: fetched {len(all_hosts):,} of {expected:,} "
                        f"(page {page})"
                    )
                else:
                    logger.info(
                        f"  VM hosts: fetched {len(all_hosts)} so far (page {page})"
                    )

            next_url = self._get_pagination_url(response.text)
            if not next_url:
                break

            if self._rate_limiter:
                self._rate_limiter.acquire()
            try:
                session = self._get_vm_session()
                response = session.get(next_url, timeout=120)
            except requests.RequestException as e:
                logger.error(f"VM host pagination failed: {e}")
                break

        if expected is not None and len(all_hosts) != expected:
            logger.warning(
                f"VM hosts: fetched {len(all_hosts):,} but count endpoint "
                f"reported {expected:,} (drift of {len(all_hosts) - expected:+,})"
            )
        logger.info(f"Fetched {len(all_hosts)} VM hosts total")
        return all_hosts

    def _parse_vm_hosts_xml(self, xml_text: str) -> List[Dict]:
        hosts = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            logger.error(f"Failed to parse VM hosts XML: {e}")
            return hosts

        for host_elem in root.findall(".//HOST"):
            host = {
                "host_id": self._get_xml_int(host_elem, "ID"),
                "ip": self._get_xml_text(host_elem, "IP"),
                "dns": self._get_xml_text(host_elem, "DNS"),
                "netbios": self._get_xml_text(host_elem, "NETBIOS"),
                "os": self._get_xml_text(host_elem, "OS"),
                "trurisk_score": self._get_xml_int(host_elem, "TRURISK_SCORE"),
                "last_scan_date": self._get_xml_text(host_elem, "LAST_SCAN_DATETIME"),
                "last_vm_scanned_date": self._get_xml_text(host_elem, "LAST_VM_SCANNED_DATE"),
                "last_activity_date": self._get_xml_text(host_elem, "LAST_ACTIVITY"),
                "tracking_method": self._get_xml_text(host_elem, "TRACKING_METHOD"),
                "tags": [],
            }
            # Parse tags
            for tag_elem in host_elem.findall(".//TAGS/TAG"):
                host["tags"].append({
                    "tag_id": self._get_xml_int(tag_elem, "TAG_ID"),
                    "tag_name": self._get_xml_text(tag_elem, "NAME"),
                })
            hosts.append(host)
        return hosts

    # ── Fetch VM Detections ──────────────────────────────────────

    def fetch_vm_detections(self, max_pages: int = 500,
                            expected: Optional[int] = None) -> List[Dict]:
        """Fetch all host detections from VM Detection API v5.

        If `expected` is given (from count_vm_detections()), logs it upfront
        and warns if the fetched total drifts."""
        if expected is not None:
            logger.info(f"Fetching VM detections... (expected: {expected:,})")
        else:
            logger.info("Fetching VM detections...")
        all_detections = []
        page = 0

        response = self._vm_request(
            "POST",
            "/api/5.0/fo/asset/host/vm/detection/",
            data={
                "action": "list",
                "truncation_limit": 1000,
                "show_tags": 1,
                "show_qds": 1,
                "show_results": 0,
            },
            timeout=180,
        )

        while page < max_pages:
            page += 1
            detections = self._parse_vm_detections_xml(response.text)
            all_detections.extend(detections)

            if page % 10 == 0:
                if expected:
                    logger.info(
                        f"  VM detections: fetched {len(all_detections):,} of "
                        f"{expected:,} (page {page})"
                    )
                else:
                    logger.info(
                        f"  VM detections: fetched {len(all_detections)} so far "
                        f"(page {page})"
                    )

            next_url = self._get_pagination_url(response.text)
            if not next_url:
                break

            if self._rate_limiter:
                self._rate_limiter.acquire()
            try:
                session = self._get_vm_session()
                response = session.get(next_url, timeout=180)
            except requests.RequestException as e:
                logger.error(f"VM detection pagination failed: {e}")
                break

        if expected is not None and len(all_detections) != expected:
            logger.warning(
                f"VM detections: fetched {len(all_detections):,} but count "
                f"endpoint reported {expected:,} "
                f"(drift of {len(all_detections) - expected:+,})"
            )
        logger.info(f"Fetched {len(all_detections)} VM detections total")
        return all_detections

    def _parse_vm_detections_xml(self, xml_text: str) -> List[Dict]:
        detections = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            logger.error(f"Failed to parse VM detections XML: {e}")
            return detections

        for host_elem in root.findall(".//HOST"):
            host_id = self._get_xml_int(host_elem, "ID")
            ip = self._get_xml_text(host_elem, "IP")
            os_text = self._get_xml_text(host_elem, "OS")

            # Host-level tags
            host_tags = []
            for tag_elem in host_elem.findall(".//TAGS/TAG"):
                host_tags.append({
                    "tag_id": self._get_xml_int(tag_elem, "TAG_ID"),
                    "tag_name": self._get_xml_text(tag_elem, "NAME"),
                })

            for det_elem in host_elem.findall(".//DETECTION"):
                qds_elem = det_elem.find("QDS")
                qds_val = 0
                if qds_elem is not None and qds_elem.text:
                    try:
                        qds_val = int(qds_elem.text)
                    except ValueError:
                        pass

                detection = {
                    "host_id": host_id,
                    "ip": ip,
                    "os": os_text,
                    "qid": self._get_xml_int(det_elem, "QID"),
                    "type": self._get_xml_text(det_elem, "TYPE"),
                    "severity": self._get_xml_int(det_elem, "SEVERITY"),
                    "status": self._get_xml_text(det_elem, "STATUS"),
                    "is_disabled": self._get_xml_text(det_elem, "IS_DISABLED", "0") == "1",
                    "qds": qds_val,
                    "first_found": self._get_xml_text(det_elem, "FIRST_FOUND_DATETIME"),
                    "last_found": self._get_xml_text(det_elem, "LAST_FOUND_DATETIME"),
                    "last_fixed": self._get_xml_text(det_elem, "LAST_FIXED_DATETIME"),
                    "last_test": self._get_xml_text(det_elem, "LAST_TEST_DATETIME"),
                    "times_found": self._get_xml_int(det_elem, "TIMES_FOUND"),
                    "results": self._get_xml_text(det_elem, "RESULTS"),
                    "host_tags": host_tags,
                }
                detections.append(detection)
        return detections

    # ── Fetch CSAM Assets ────────────────────────────────────────

    def fetch_csam_assets(self, max_pages: int = 500,
                          expected: Optional[int] = None,
                          page_size: Optional[int] = None,
                          lookback_days: Optional[int] = None,
                          resume_from_id: Optional[str] = None,
                          on_page: Optional[Callable[[int, int, Optional[str], bool], None]] = None
                          ) -> List[Dict]:
        """Fetch assets from CSAM Asset Host Data API.

        Parameters
        ----------
        max_pages : safety cap on pagination loops.
        expected  : total from count_csam_assets() for progress / drift logging.
        page_size : assets per request (1-1000). Defaults to config.csam_page_size.
        lookback_days : if > 0, server-side filter restricts to assets whose
            `lastCheckedIn` is within the last N days. 0 / None = no filter.
            If Qualys rejects the filter on the first page, we log a warning
            and retry once without it (so an unknown QQL field can't break
            the whole refresh).
        resume_from_id : Qualys asset ID to pass as `startFromId` on the very
            first page. Used to resume after a rate-limited / crashed run.
        on_page : optional callback fired AFTER each successful page as
            `on_page(page_num, assets_fetched_so_far, last_seen_id, has_more)`.
            The caller uses this to persist a resume checkpoint after every
            page, so even a kill-9 mid-pull leaves us resumable.

        Returns the full list of asset dicts. If `RateLimitError` or any
        other exception bubbles up, `on_page` will already have been called
        for every page we successfully consumed, so the checkpoint is current.
        """
        if page_size is None:
            page_size = getattr(self.config, "csam_page_size", 1000)
        # Qualys CSAM search accepts up to 1000; cap defensively.
        page_size = max(1, min(int(page_size), 1000))

        # Resolve lookback: explicit arg wins, otherwise config default.
        if lookback_days is None:
            lookback_days = getattr(self.config, "csam_lookback_days", 0)
        # Set filter_enabled up front; may be cleared by the 400-fallback below.
        filter_enabled = bool(lookback_days and lookback_days > 0)
        filter_qql: Optional[str] = None
        if filter_enabled:
            cutoff = datetime.utcnow() - timedelta(days=int(lookback_days))
            cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
            # QQL range syntax supported by CSAM v2 search.
            filter_qql = f"lastCheckedIn >= '{cutoff_iso}'"

        banner_bits = [f"page_size: {page_size}"]
        if expected is not None:
            banner_bits.insert(0, f"expected: {expected:,}")
        if filter_enabled:
            banner_bits.append(f"lookback: {lookback_days}d")
        if resume_from_id:
            banner_bits.append(f"resume_from_id: {resume_from_id}")
        logger.info(f"Fetching CSAM assets... ({', '.join(banner_bits)})")

        all_assets: List[Dict] = []
        last_seen_id: Optional[str] = resume_from_id
        page = 0

        while page < max_pages:
            page += 1
            body: Dict[str, Any] = {
                "ServiceRequest": {
                    "preferences": {
                        "limitResults": page_size,
                    }
                }
            }
            if last_seen_id:
                body["ServiceRequest"]["preferences"]["startFromId"] = last_seen_id
            if filter_enabled and filter_qql:
                # CSAM v2 search accepts a QQL `filter` string at the
                # ServiceRequest level.
                body["ServiceRequest"]["filter"] = filter_qql

            response = self._csam_request(
                "POST",
                "/rest/2.0/search/am/asset",
                json_body=body,
                timeout=120,
            )

            # Defensive filter fallback: if Qualys rejects the filter with a
            # 4xx on the FIRST page only, drop it and retry. This guards
            # against QQL field-name drift without breaking refreshes.
            if (response.status_code == 400 and filter_enabled
                    and page == 1 and not resume_from_id):
                logger.warning(
                    "CSAM rejected lookback filter (HTTP 400). Retrying "
                    "without the 'lastCheckedIn' filter. Check Qualys docs "
                    "if this tenant uses a different field name."
                )
                filter_enabled = False
                page -= 1  # redo page 1 without filter
                continue

            if response.status_code != 200:
                raise QualysError(
                    f"CSAM API returned {response.status_code}: {response.text[:200]}"
                )

            data = response.json()
            resp_data = data.get("ServiceResponse", data)
            response_code = resp_data.get("responseCode", "")

            if response_code not in ("SUCCESS", ""):
                error_msg = resp_data.get("responseErrorDetails", {}).get("errorMessage", response_code)
                # Same fallback path as the 400 branch above — if the filter
                # was the problem, try once without it.
                if (filter_enabled and page == 1 and not resume_from_id
                        and "filter" in str(error_msg).lower()):
                    logger.warning(
                        f"CSAM filter rejected: {error_msg}. Retrying "
                        f"without the lookback filter."
                    )
                    filter_enabled = False
                    page -= 1
                    continue
                raise QualysError(f"CSAM API error: {error_msg}")

            asset_list = resp_data.get("data", resp_data.get("assetListData", {}))
            if isinstance(asset_list, dict):
                assets = asset_list.get("asset", asset_list.get("HostAsset", []))
            elif isinstance(asset_list, list):
                assets = asset_list
            else:
                assets = []

            if isinstance(assets, dict):
                assets = [assets]

            all_assets.extend(assets)

            has_more = resp_data.get("hasMoreRecords", resp_data.get("hasMore", False))
            last_seen_id = resp_data.get("lastSeenAssetId", resp_data.get("lastId"))

            # Fire the checkpoint callback AFTER we've updated our state for
            # this page. If it raises, that's a caller bug — let it surface.
            if on_page is not None:
                try:
                    on_page(page, len(all_assets), last_seen_id, bool(has_more))
                except Exception as cb_err:
                    logger.warning(
                        f"CSAM on_page callback raised (ignored): {cb_err}"
                    )

            if page % 10 == 0:
                if expected:
                    logger.info(
                        f"  CSAM assets: fetched {len(all_assets):,} of "
                        f"{expected:,} (page {page})"
                    )
                else:
                    logger.info(
                        f"  CSAM assets: fetched {len(all_assets)} so far "
                        f"(page {page})"
                    )

            if not has_more or not last_seen_id:
                break

        if expected is not None and len(all_assets) != expected:
            logger.warning(
                f"CSAM assets: fetched {len(all_assets):,} but count endpoint "
                f"reported {expected:,} (drift of {len(all_assets) - expected:+,})"
            )
        logger.info(f"Fetched {len(all_assets)} CSAM assets total")
        return all_assets

    # ── Tag Extraction Helpers ───────────────────────────────────

    @staticmethod
    def extract_tags_from_csam(assets: List[Dict]) -> List[Dict]:
        """Extract normalized tag records from CSAM assets."""
        tags = []
        for asset in assets:
            ip = asset.get("address", asset.get("ipAddress", ""))
            asset_id = asset.get("assetId", asset.get("id", ""))
            tag_list = asset.get("tagList", {})
            if isinstance(tag_list, dict):
                tag_items = tag_list.get("tag", [])
            elif isinstance(tag_list, list):
                tag_items = tag_list
            else:
                tag_items = []
            if isinstance(tag_items, dict):
                tag_items = [tag_items]
            for t in tag_items:
                tags.append({
                    "host_id": asset_id,
                    "ip_address": ip,
                    "tag_id": t.get("tagId", 0),
                    "tag_name": t.get("tagName", ""),
                    "criticality_score": t.get("criticalityScore"),
                    "source": "csam",
                })
        return tags

    @staticmethod
    def extract_tags_from_vm_hosts(hosts: List[Dict]) -> List[Dict]:
        """Extract normalized tag records from VM host data."""
        tags = []
        for host in hosts:
            host_id = host.get("host_id", 0)
            ip = host.get("ip", "")
            for t in host.get("tags", []):
                tags.append({
                    "host_id": host_id,
                    "ip_address": ip,
                    "tag_id": t.get("tag_id", 0),
                    "tag_name": t.get("tag_name", ""),
                    "criticality_score": None,
                    "source": "vm",
                })
        return tags

    @staticmethod
    def extract_tags_from_detections(detections: List[Dict]) -> List[Dict]:
        """Extract normalized tag records from VM detection data (host-level tags)."""
        seen = set()
        tags = []
        for det in detections:
            host_id = det.get("host_id", 0)
            ip = det.get("ip", "")
            for t in det.get("host_tags", []):
                key = (host_id, t.get("tag_id", 0))
                if key not in seen:
                    seen.add(key)
                    tags.append({
                        "host_id": host_id,
                        "ip_address": ip,
                        "tag_id": t.get("tag_id", 0),
                        "tag_name": t.get("tag_name", ""),
                        "criticality_score": None,
                        "source": "vm",
                    })
        return tags
