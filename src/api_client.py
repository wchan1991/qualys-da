"""
Qualys API Client

Dual-auth client supporting:
- VM APIs (Basic auth via session login) — XML responses
- CSAM API (Bearer token via gateway auth) — JSON responses

Includes rate limiting, pagination, retry, and XML/JSON parsing.
"""

import time
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

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
    """Token bucket rate limiter."""
    calls_per_minute: int
    burst_limit: int = 10
    _tokens: float = None
    _last_update: float = None

    def __post_init__(self):
        self._tokens = float(self.burst_limit)
        self._last_update = time.time()

    def acquire(self) -> float:
        now = time.time()
        elapsed = now - self._last_update
        refill_rate = self.calls_per_minute / 60.0
        self._tokens = min(self.burst_limit, self._tokens + elapsed * refill_rate)
        self._last_update = now
        if self._tokens >= 1:
            self._tokens -= 1
            return 0.0
        wait_time = (1 - self._tokens) / refill_rate
        time.sleep(wait_time)
        self._tokens = 0
        self._last_update = time.time()
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
        if self._csam_token and self._csam_token_expires:
            if datetime.now() < self._csam_token_expires:
                return

        logger.info("Authenticating with Qualys CSAM API...")
        session = self._get_csam_session()
        url = f"{self.config.csam_base_url}/auth"

        try:
            response = session.post(
                url,
                json={
                    "username": self.config.username,
                    "password": self.config.password,
                },
                timeout=self.config.timeout,
            )
            if response.status_code == 200:
                data = response.json()
                self._csam_token = data.get("token", data.get("access_token", ""))
                if not self._csam_token:
                    # Some CSAM endpoints return token in Authorization header
                    self._csam_token = response.headers.get("Authorization", "").replace("Bearer ", "")
                if self._csam_token:
                    self._csam_token_expires = datetime.now() + timedelta(hours=4)
                    session.headers["Authorization"] = f"Bearer {self._csam_token}"
                    logger.info("CSAM authentication successful")
                else:
                    raise AuthError("CSAM auth: no token in response")
            else:
                raise AuthError(f"CSAM authentication failed: HTTP {response.status_code}")
        except requests.RequestException as e:
            raise AuthError(f"CSAM authentication request failed: {e}")

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
            if response.status_code == 429:
                raise RateLimitError("CSAM API rate limit exceeded")
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

    def fetch_vm_hosts(self, max_pages: int = 500) -> List[Dict]:
        """Fetch all hosts from VM Host List API v3."""
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
                logger.info(f"  VM hosts: fetched {len(all_hosts)} so far (page {page})")

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

    def fetch_vm_detections(self, max_pages: int = 500) -> List[Dict]:
        """Fetch all host detections from VM Detection API v5."""
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
                logger.info(f"  VM detections: fetched {len(all_detections)} so far (page {page})")

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

    def fetch_csam_assets(self, max_pages: int = 500) -> List[Dict]:
        """Fetch all assets from CSAM Asset Host Data API."""
        logger.info("Fetching CSAM assets...")
        all_assets = []
        last_seen_id = None
        page = 0

        while page < max_pages:
            page += 1
            body = {
                "ServiceRequest": {
                    "preferences": {
                        "limitResults": 300,
                    }
                }
            }
            if last_seen_id:
                body["ServiceRequest"]["preferences"]["startFromId"] = last_seen_id

            response = self._csam_request(
                "POST",
                "/rest/2.0/search/am/asset",
                json_body=body,
                timeout=120,
            )

            if response.status_code != 200:
                raise QualysError(
                    f"CSAM API returned {response.status_code}: {response.text[:200]}"
                )

            data = response.json()
            resp_data = data.get("ServiceResponse", data)
            response_code = resp_data.get("responseCode", "")

            if response_code not in ("SUCCESS", ""):
                error_msg = resp_data.get("responseErrorDetails", {}).get("errorMessage", response_code)
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

            if page % 10 == 0:
                logger.info(f"  CSAM assets: fetched {len(all_assets)} so far (page {page})")

            has_more = resp_data.get("hasMoreRecords", resp_data.get("hasMore", False))
            last_seen_id = resp_data.get("lastSeenAssetId", resp_data.get("lastId"))

            if not has_more or not last_seen_id:
                break

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
