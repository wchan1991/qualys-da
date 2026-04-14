#!/usr/bin/env python3
"""
Seed Qualys DA with realistic dummy data for testing.

Generates:
  - 120 hosts (CSAM + VM), 90 in both sources, 15 VM-only, 15 CSAM-only
  - 2,700 detections: ~12% sev5, ~30% sev4, ~28% sev3, ~20% sev2, ~10% sev1
  - 12 tags assigned across hosts
  - 6 ownership rules covering ~80% of hosts
  - 52 weeks of weekly rollups + 12 monthly rollups (full year of trending data)
  - ~200 detection changes (new/fixed/reopened over last 4 weeks)
  - 1 refresh log entry

Usage: python seed_data.py [--reset]
  --reset  Wipe existing data before seeding
"""

import sys
import json
import random
import argparse
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.database import QualysDADatabase

# ── Configuration ────────────────────────────────────────────

NUM_HOSTS = 120
NUM_BOTH = 90          # Hosts in both CSAM and VM
NUM_VM_ONLY = 15       # VM-only hosts
NUM_CSAM_ONLY = 15     # CSAM-only hosts
NUM_ORPHANS = 10       # Of NUM_HOSTS, how many to place on the unowned 10.99.x.x subnet
                       # These hosts match NO ownership rule — show up in "Orphaned Assets"
NUM_DETECTIONS = 3200
NUM_WEEKS_HISTORY = 52
NUM_MONTHS_HISTORY = 12
NUM_CHANGES = 800

NOW = datetime.utcnow()
FETCHED_AT = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Severity distribution ────────────────────────────────────
# Weights: sev5=12%, sev4=30%, sev3=28%, sev2=20%, sev1=10%
SEV_WEIGHTS = [10, 20, 28, 30, 12]  # index 0=sev1 .. index 4=sev5

# ── Reference data ───────────────────────────────────────────

OS_LIST = [
    "Windows Server 2022 Standard",
    "Windows Server 2019 Datacenter",
    "Windows 11 Enterprise 24H2",
    "Windows 10 Enterprise 22H2",
    "Red Hat Enterprise Linux 9.3",
    "Red Hat Enterprise Linux 8.9",
    "Ubuntu 22.04.4 LTS",
    "Ubuntu 24.04 LTS",
    "CentOS Stream 9",
    "SUSE Linux Enterprise 15 SP5",
    "Debian 12.5",
    "Oracle Linux 8.9",
    "VMware Photon OS 5.0",
    "Amazon Linux 2023",
]

HOSTNAMES = [
    "web", "app", "db", "api", "cache", "proxy", "auth", "mail",
    "file", "dns", "ldap", "ntp", "log", "monitor", "backup",
    "ci", "git", "vault", "consul", "kafka", "rabbit", "redis",
    "elastic", "grafana", "jenkins", "harbor", "k8s-node", "bastion",
]

ENVS = ["prod", "staging", "dev", "uat", "dr"]
DOMAINS = ["corp.local", "internal.net", "infra.local"]

TAGS = [
    {"id": 1001, "name": "Production", "crit": 5},
    {"id": 1002, "name": "Staging", "crit": 3},
    {"id": 1003, "name": "Development", "crit": 1},
    {"id": 1004, "name": "PCI-DSS Scope", "crit": 5},
    {"id": 1005, "name": "Internet Facing", "crit": 5},
    {"id": 1006, "name": "Windows Servers", "crit": 3},
    {"id": 1007, "name": "Linux Servers", "crit": 3},
    {"id": 1008, "name": "Database Tier", "crit": 4},
    {"id": 1009, "name": "Web Tier", "crit": 4},
    {"id": 1010, "name": "Legacy Systems", "crit": 2},
    {"id": 1011, "name": "Cloud Hosted", "crit": 3},
    {"id": 1012, "name": "Critical Infrastructure", "crit": 5},
]

OWNERS = [
    {"type": "ip_range", "value": "10.1.0.0/16", "owner": "Alice Chen", "bu": "Infrastructure"},
    {"type": "ip_range", "value": "10.2.0.0/16", "owner": "Bob Martinez", "bu": "Application Dev"},
    {"type": "ip_range", "value": "10.3.0.0/16", "owner": "Carol White", "bu": "Data Services"},
    {"type": "tag", "value": "PCI-DSS Scope", "owner": "Dave Kim", "bu": "Compliance"},
    {"type": "os_pattern", "value": "Red Hat%", "owner": "Eve Johnson", "bu": "Platform Eng"},
    {"type": "os_pattern", "value": "Ubuntu%", "owner": "Frank Liu", "bu": "Platform Eng"},
]

# Common QIDs with realistic names + CVE/CVSS/vendor/product/package/fix_version metadata
# Tuple shape: (qid, title, detection_type, cve_id, cvss_base, vendor, product, package, pkg_version, fix_version, patchable)
QIDS = [
    (90001, "SSL Certificate Expired", "Confirmed", None, 5.3, "OpenSSL", "OpenSSL", "openssl", "1.1.1k", "1.1.1w", False),
    (90002, "OpenSSL Heartbleed", "Confirmed", "CVE-2014-0160", 7.5, "OpenSSL", "OpenSSL", "openssl", "1.0.1f", "1.0.1g", True),
    (90003, "Apache Log4j RCE", "Confirmed", "CVE-2021-44228", 10.0, "Apache", "Log4j", "log4j-core", "2.14.1", "2.17.1", True),
    (90004, "MS Exchange ProxyLogon", "Confirmed", "CVE-2021-26855", 9.8, "Microsoft", "Exchange Server", "exchange-server", "15.2.721", "15.2.721.13", True),
    (90005, "SMBv1 Enabled", "Confirmed", None, 5.0, "Microsoft", "Windows", "smb", "1.0", "disabled", False),
    (90006, "TLS 1.0 Enabled", "Confirmed", None, 3.7, "Various", "TLS", "openssl", "1.1.1", "1.1.1w", False),
    (90007, "Weak SSH Algorithms", "Confirmed", None, 5.3, "OpenBSD", "OpenSSH", "openssh", "7.4", "9.6", True),
    (90008, "OpenSSH RegreSSHion", "Confirmed", "CVE-2024-6387", 8.1, "OpenBSD", "OpenSSH", "openssh-server", "8.5p1", "9.8p1", True),
    (90009, "Apache HTTP Path Traversal", "Confirmed", "CVE-2021-41773", 7.5, "Apache", "HTTP Server", "httpd", "2.4.49", "2.4.51", True),
    (90010, "PostgreSQL Privilege Escalation", "Confirmed", "CVE-2022-1552", 8.8, "PostgreSQL", "PostgreSQL", "postgresql", "14.2", "14.3", True),
    (90011, "Nginx Buffer Overflow", "Confirmed", "CVE-2022-41741", 7.1, "F5", "Nginx", "nginx", "1.20.0", "1.23.2", True),
    (90012, "Linux Kernel DirtyPipe", "Confirmed", "CVE-2022-0847", 7.8, "Linux", "Kernel", "linux-image", "5.15.0", "5.17.1", True),
    (90013, "Docker Container Escape", "Confirmed", "CVE-2022-0492", 7.0, "Docker", "Docker Engine", "docker-ce", "20.10.12", "20.10.14", True),
    (90014, "Kubernetes API Auth Bypass", "Confirmed", "CVE-2023-2728", 6.5, "Kubernetes", "kube-apiserver", "kubernetes", "1.24.0", "1.24.14", True),
    (90015, "Redis Unauthorized Access", "Confirmed", "CVE-2022-0543", 10.0, "Redis", "Redis", "redis-server", "6.0.16", "6.0.17", True),
    (90016, "MongoDB Auth Bypass", "Confirmed", "CVE-2021-20333", 7.5, "MongoDB", "MongoDB", "mongodb", "4.4.8", "4.4.9", True),
    (90017, "Windows Print Spooler RCE", "Confirmed", "CVE-2021-34527", 8.8, "Microsoft", "Windows", "spoolsv", "10.0.19041", "10.0.19041.1110", True),
    (90018, "IIS WebDAV Vulnerability", "Confirmed", "CVE-2022-21907", 9.8, "Microsoft", "IIS", "http.sys", "10.0.17763", "10.0.17763.2452", True),
    (90019, "SNMP Default Community String", "Potential", None, 5.0, "Net-SNMP", "SNMP", "snmpd", "5.9.1", "5.9.3", False),
    (90020, "DNS Zone Transfer Allowed", "Potential", None, 5.3, "ISC", "BIND", "bind9", "9.16", "9.16.42", False),
    (90021, "FTP Anonymous Access", "Potential", None, 5.0, "Generic", "FTP", "vsftpd", "3.0.3", "config-change", False),
    (90022, "NTP Amplification", "Potential", "CVE-2014-9295", 7.5, "NTP Project", "ntpd", "ntp", "4.2.6p5", "4.2.8p17", True),
    (90023, "HTTP TRACE Method Enabled", "Potential", None, 4.3, "Generic", "HTTP", "httpd", "2.4", "config-change", False),
    (90024, "Missing HTTP Security Headers", "Info", None, 2.6, "Generic", "HTTP", "web-server", "-", "config-change", False),
    (90025, "SSL Certificate Weak Signature", "Confirmed", None, 5.3, "OpenSSL", "OpenSSL", "openssl", "1.0.2", "1.1.1w", True),
    (90026, "SSH Root Login Permitted", "Confirmed", None, 7.2, "OpenBSD", "OpenSSH", "openssh-server", "8.0", "config-change", False),
    (90027, "Java Deserialization RCE", "Confirmed", "CVE-2023-34040", 9.8, "Oracle", "Java", "openjdk-11", "11.0.18", "11.0.21", True),
    (90028, "PHP RCE", "Confirmed", "CVE-2024-4577", 9.8, "PHP Group", "PHP", "php", "8.1.28", "8.1.29", True),
    (90029, "WordPress Core Vulnerability", "Confirmed", "CVE-2023-5561", 5.3, "Automattic", "WordPress", "wordpress", "6.3.1", "6.3.2", True),
    (90030, "Samba SmbLeed", "Confirmed", "CVE-2020-1472", 10.0, "Samba Team", "Samba", "samba", "4.11.0", "4.11.16", True),
    (90031, "Grafana Auth Bypass", "Confirmed", "CVE-2022-21702", 6.5, "Grafana Labs", "Grafana", "grafana", "8.3.4", "8.3.5", True),
    (90032, "Jenkins Script Console Exposed", "Confirmed", "CVE-2024-23897", 9.8, "Jenkins", "Jenkins", "jenkins", "2.426.2", "2.426.3", True),
    (90033, "Elasticsearch Unrestricted Access", "Potential", "CVE-2021-22134", 7.5, "Elastic", "Elasticsearch", "elasticsearch", "7.11.2", "7.12.0", True),
    (90034, "RDP BlueKeep", "Confirmed", "CVE-2019-0708", 9.8, "Microsoft", "Windows", "rdp", "10.0.17134", "10.0.17134.858", True),
    (90035, "sudo Privilege Escalation", "Confirmed", "CVE-2021-3156", 7.8, "Sudo Project", "sudo", "sudo", "1.9.5p1", "1.9.5p2", True),
    (90036, "Citrix ADC Path Traversal", "Confirmed", "CVE-2023-3519", 9.8, "Citrix", "NetScaler ADC", "netscaler-adc", "13.1-48", "13.1-49.13", True),
    (90037, "VMware vCenter RCE", "Confirmed", "CVE-2021-21985", 9.8, "VMware", "vCenter Server", "vcenter", "7.0.0", "7.0.2", True),
    (90038, "Fortinet FortiOS Auth Bypass", "Confirmed", "CVE-2022-40684", 9.8, "Fortinet", "FortiOS", "fortios", "7.2.1", "7.2.2", True),
    (90039, "SSL/TLS ROBOT Attack", "Confirmed", "CVE-2017-13099", 5.9, "Various", "TLS", "openssl", "1.0.2k", "1.0.2m", True),
    (90040, "HTTP/2 Rapid Reset", "Confirmed", "CVE-2023-44487", 7.5, "Various", "HTTP/2", "nginx", "1.25.1", "1.25.3", True),
]

SOFTWARE = [
    {"name": "Apache HTTP Server", "version": "2.4.58"},
    {"name": "OpenSSH", "version": "9.6"},
    {"name": "Nginx", "version": "1.25.4"},
    {"name": "PostgreSQL", "version": "16.2"},
    {"name": "Redis", "version": "7.2.4"},
    {"name": "Docker Engine", "version": "25.0.3"},
    {"name": "Python", "version": "3.12.2"},
    {"name": "Node.js", "version": "20.11.1"},
    {"name": "Java OpenJDK", "version": "21.0.2"},
    {"name": "Elasticsearch", "version": "8.12"},
]


def random_ip(subnet_idx):
    """Generate IP in 10.{subnet}.x.x range."""
    s = (subnet_idx % 3) + 1  # 10.1.x.x, 10.2.x.x, 10.3.x.x
    return f"10.{s}.{random.randint(1,254)}.{random.randint(1,254)}"


def random_date(days_back_max, days_back_min=0):
    """Random datetime in the past N days."""
    delta = timedelta(days=random.randint(days_back_min, days_back_max))
    return (NOW - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def pick_severity():
    """Pick severity 1-5 matching the target distribution."""
    return random.choices([1, 2, 3, 4, 5], weights=SEV_WEIGHTS, k=1)[0]


def pick_status(severity, first_found_days_ago):
    """Pick a status weighted by severity and age."""
    if first_found_days_ago > 120:
        # Older vulns more likely fixed
        weights = [5, 25, 50, 20]  # New, Active, Fixed, Re-Opened
    elif severity >= 4:
        # Critical/high: more active, some fixed
        weights = [15, 45, 25, 15]
    else:
        weights = [10, 55, 25, 10]
    return random.choices(["New", "Active", "Fixed", "Re-Opened"], weights=weights, k=1)[0]


def generate_hosts():
    """Generate host records."""
    hosts = []
    # Orphan OSes: not matched by any os_pattern in OWNERS (avoid Red Hat* and Ubuntu*)
    ORPHAN_OS_LIST = [os for os in OS_LIST if not os.startswith(("Red Hat", "Ubuntu"))]
    # Non-PCI tags (ensures no owner via tag rule)
    NON_PCI_TAGS = [t for t in TAGS if t["name"] != "PCI-DSS Scope"]
    # Orphans get placed at index 0..NUM_ORPHANS-1 of the VM-only slice
    # so orphans are still scanned (have detections) but have no owner.
    orphan_indexes = set(range(NUM_BOTH, NUM_BOTH + min(NUM_ORPHANS, NUM_VM_ONLY)))

    for i in range(NUM_HOSTS):
        host_id = 10000 + i
        is_orphan = i in orphan_indexes
        if is_orphan:
            # Unowned subnet (10.99.x.x), non-matched OS, no PCI tag
            ip = f"10.99.{random.randint(1,254)}.{random.randint(1,254)}"
            os = random.choice(ORPHAN_OS_LIST)
        else:
            ip = random_ip(i)
            os = random.choice(OS_LIST)
        hostname = f"{random.choice(HOSTNAMES)}-{random.choice(ENVS)}-{i:03d}"
        domain = random.choice(DOMAINS)
        dns = f"{hostname}.{domain}"
        trurisk = random.randint(50, 950)
        last_scan_days = random.choices([1, 3, 7, 14, 35, 60], weights=[30, 25, 20, 15, 7, 3], k=1)[0]
        last_scan = (NOW - timedelta(days=last_scan_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Assign tags (2-4 per host) — orphans skip the PCI-DSS tag
        tag_pool = NON_PCI_TAGS if is_orphan else TAGS
        host_tags = random.sample(tag_pool, k=random.randint(2, 4))
        # OS-based tag
        if "Windows" in os and {"id": 1006, "name": "Windows Servers", "crit": 3} not in host_tags:
            host_tags.append({"id": 1006, "name": "Windows Servers", "crit": 3})
        elif "Windows" not in os and {"id": 1007, "name": "Linux Servers", "crit": 3} not in host_tags:
            host_tags.append({"id": 1007, "name": "Linux Servers", "crit": 3})

        # Determine source membership
        if i < NUM_BOTH:
            in_csam, in_vm = True, True
        elif i < NUM_BOTH + NUM_VM_ONLY:
            in_csam, in_vm = False, True
        else:
            in_csam, in_vm = True, False

        hosts.append({
            "host_id": host_id,
            "ip": ip,
            "dns": dns,
            "hostname": hostname,
            "netbios": hostname.upper()[:15],
            "os": os,
            "trurisk_score": trurisk,
            "last_scan_date": last_scan,
            "last_scan_days": last_scan_days,
            "tracking_method": random.choice(["IP", "AGENT", "DNS"]),
            "tags": host_tags,
            "in_csam": in_csam,
            "in_vm": in_vm,
            "software": random.sample(SOFTWARE, k=random.randint(2, 6)),
            "domain": domain,
        })
    return hosts


def generate_detections(hosts):
    """Generate detection records spread across hosts."""
    detections = []
    vm_hosts = [h for h in hosts if h["in_vm"]]

    # Generate extra QID variants to avoid dedup losses (host_id, qid must be unique)
    # Shape matches expanded QIDS tuple: qid, title, type, cve, cvss, vendor, product, pkg, ver, fix, patchable
    extra_qids = []
    for i in range(60):
        year = random.choice([2021, 2022, 2023, 2024])
        cve = f"CVE-{year}-{random.randint(1000, 49999)}" if random.random() < 0.7 else None
        cvss = round(random.uniform(2.5, 9.8), 1)
        patch = random.random() < 0.6
        extra_qids.append((
            90041 + i,
            f"Generic Vuln {i}",
            random.choice(["Confirmed", "Potential"]),
            cve,
            cvss,
            random.choice(["OpenSSL", "Microsoft", "Apache", "Oracle", "Red Hat", "Canonical", "MongoDB", "VMware"]),
            random.choice(["OpenSSL", "Windows", "HTTP Server", "Java", "Linux Kernel", "Ubuntu", "MongoDB", "vCenter"]),
            random.choice(["openssl", "kernel", "httpd", "openjdk", "nginx", "mongodb", "glibc", "systemd"]),
            f"{random.randint(1,9)}.{random.randint(0,30)}.{random.randint(0,20)}",
            f"{random.randint(1,9)}.{random.randint(0,30)}.{random.randint(0,20)}" if patch else "no-fix",
            patch,
        ))
    all_qids = QIDS + extra_qids

    for i in range(NUM_DETECTIONS):
        host = random.choice(vm_hosts)
        qid_info = random.choice(all_qids)
        qid, title, det_type, cve_id, cvss_base, vendor, product, package_name, package_version, fix_version, patchable = qid_info
        severity = pick_severity()
        # ~5% long-tail cohort: first_found 300-365 days back, fixed recently (long MTTR)
        is_long_tail = random.random() < 0.05
        if is_long_tail:
            first_found_days = random.randint(300, 365)
        else:
            first_found_days = random.randint(1, 365)
        status = pick_status(severity, first_found_days)

        first_found = (NOW - timedelta(days=first_found_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        last_found = random_date(min(first_found_days, 14))
        last_fixed = None
        if status == "Fixed":
            if is_long_tail:
                # Fixed recently — long MTTR tail
                fix_days = random.randint(0, 30)
            else:
                # Fix happens at any point between first_found + 3 days and now
                fix_days = max(0, first_found_days - random.randint(3, max(3, first_found_days)))
            last_fixed = (NOW - timedelta(days=fix_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        qds = min(100, max(1, severity * 18 + random.randint(-10, 15)))
        is_disabled = 1 if random.random() < 0.03 else 0  # 3% disabled

        # CVSS temporal is typically slightly below base
        cvss_temporal = round(max(0.0, cvss_base - random.uniform(0.1, 1.0)), 1) if cvss_base else None
        cvss_vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if cvss_base and cvss_base >= 7 else (
            f"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L" if cvss_base else None
        )

        detections.append({
            "host_id": host["host_id"],
            "ip": host["ip"],
            "qid": qid,
            "type": det_type,
            "severity": severity,
            "status": status,
            "is_disabled": is_disabled,
            "qds": qds,
            "cve_id": cve_id,
            "cvss_base": cvss_base,
            "cvss_temporal": cvss_temporal,
            "cvss_vector": cvss_vector,
            "patchable": patchable,
            "vendor": vendor,
            "product": product,
            "package_name": package_name,
            "package_version": package_version,
            "fix_version": fix_version,
            "title": title,
            "first_found": first_found,
            "last_found": last_found,
            "last_fixed": last_fixed or "",
            "last_test": last_found,
            "times_found": random.randint(1, 50),
            "results": "",
        })

    # Deduplicate (host_id, qid) — keep the first occurrence
    seen = set()
    unique = []
    for d in detections:
        key = (d["host_id"], d["qid"])
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


def generate_changes(detections):
    """Generate detection change log entries spread across the full history window.

    Events are distributed across the last NUM_WEEKS_HISTORY weeks using a
    triangular distribution with mode=0, so recent weeks see more activity
    (matches real ops where you fix more recently than long ago) but every
    month still gets some events.
    """
    changes = []
    sample_size = min(NUM_CHANGES, len(detections))
    sampled = random.sample(detections, sample_size)

    max_weeks = max(1, NUM_WEEKS_HISTORY - 1)
    for d in sampled:
        # Triangular(low, high, mode) — mode=0 weights toward recent weeks
        weeks_ago = int(random.triangular(0, max_weeks, 0))
        detected_at = (NOW - timedelta(weeks=weeks_ago, days=random.randint(0, 6))).strftime("%Y-%m-%dT%H:%M:%SZ")

        change_type = random.choices(
            ["new", "fixed", "reopened", "severity_change"],
            weights=[40, 30, 15, 15], k=1
        )[0]

        old_val, new_val = None, None
        if change_type == "new":
            new_val = d["status"]
        elif change_type == "fixed":
            old_val = "Active"
            new_val = "Fixed"
        elif change_type == "reopened":
            old_val = "Fixed"
            new_val = "Re-Opened"
        elif change_type == "severity_change":
            old_val = str(max(1, d["severity"] - 1))
            new_val = str(d["severity"])

        changes.append({
            "host_id": d["host_id"],
            "ip_address": d["ip"],
            "qid": d["qid"],
            "change_type": change_type,
            "old_value": old_val,
            "new_value": new_val,
            "severity": d["severity"],
            "detected_at": detected_at,
        })
    return changes


def generate_weekly_rollups(detections, hosts):
    """Generate 12 weeks of historical rollup data with realistic trends."""
    rollups = []
    base_total = len([d for d in detections if d["status"] != "Fixed"])
    total_hosts = len(hosts)

    for w in range(NUM_WEEKS_HISTORY, 0, -1):
        week_start = (NOW - timedelta(weeks=w))
        # Align to Monday
        week_start = week_start - timedelta(days=week_start.weekday())
        week_str = week_start.strftime("%Y-%m-%d")

        # Simulate gradual improvement trend with noise
        progress = (NUM_WEEKS_HISTORY - w) / NUM_WEEKS_HISTORY
        drift = random.uniform(-0.05, 0.05)
        total = int(base_total * (1.1 - 0.15 * progress + drift))

        sev5 = int(total * random.uniform(0.10, 0.14))
        sev4 = int(total * random.uniform(0.28, 0.32))
        sev3 = int(total * random.uniform(0.26, 0.30))
        sev2 = int(total * random.uniform(0.18, 0.22))
        sev1 = total - sev5 - sev4 - sev3 - sev2

        new_w = random.randint(20, 80)
        fixed_w = random.randint(25, 90)

        rollups.append({
            "week_start": week_str,
            "total_vulns": total,
            "sev5_count": sev5,
            "sev4_count": sev4,
            "sev3_count": sev3,
            "sev2_count": sev2,
            "sev1_count": max(0, sev1),
            "status_new": int(total * 0.12),
            "status_active": int(total * 0.55),
            "status_fixed": int(total * 0.23),
            "status_reopened": int(total * 0.10),
            "new_this_week": new_w,
            "fixed_this_week": fixed_w,
            "avg_trurisk": round(random.uniform(280, 420), 1),
            "max_trurisk": random.randint(800, 950),
            "avg_qds": round(random.uniform(45, 65), 1),
            "total_hosts": total_hosts + random.randint(-3, 3),
            "csam_hosts": NUM_BOTH + NUM_CSAM_ONLY + random.randint(-2, 2),
            "vm_hosts": NUM_BOTH + NUM_VM_ONLY + random.randint(-2, 2),
            "both_hosts": NUM_BOTH + random.randint(-2, 2),
            "coverage_pct": round(random.uniform(82, 92), 1),
            "aging_30d": int(total * random.uniform(0.40, 0.55)),
            "aging_60d": int(total * random.uniform(0.25, 0.35)),
            "aging_90d": int(total * random.uniform(0.10, 0.20)),
            "tag_metrics": {},
        })
    return rollups


def generate_monthly_rollups(weekly_rollups):
    """Aggregate weekly rollups into NUM_MONTHS_HISTORY monthly rollups."""
    monthly = []
    for m in range(NUM_MONTHS_HISTORY, 0, -1):
        month_start = (NOW - timedelta(days=30 * m)).replace(day=1)
        month_str = month_start.strftime("%Y-%m-01")

        # Average the weekly rollups that fall in this month
        relevant = [r for r in weekly_rollups if r["week_start"][:7] == month_start.strftime("%Y-%m")]
        if not relevant:
            # Fall back to nearest week to avoid empty months
            idx = min(m * 4, len(weekly_rollups) - 1)
            relevant = [weekly_rollups[idx]]

        avg = lambda key: int(sum(r.get(key, 0) for r in relevant) / len(relevant))
        avg_f = lambda key: round(sum(r.get(key, 0) for r in relevant) / len(relevant), 1)

        monthly.append({
            "month_start": month_str,
            "total_vulns": avg("total_vulns"),
            "sev5_count": avg("sev5_count"),
            "sev4_count": avg("sev4_count"),
            "sev3_count": avg("sev3_count"),
            "sev2_count": avg("sev2_count"),
            "sev1_count": avg("sev1_count"),
            "status_new": avg("status_new"),
            "status_active": avg("status_active"),
            "status_fixed": avg("status_fixed"),
            "status_reopened": avg("status_reopened"),
            "new_this_month": sum(r.get("new_this_week", 0) for r in relevant),
            "fixed_this_month": sum(r.get("fixed_this_week", 0) for r in relevant),
            "avg_trurisk": avg_f("avg_trurisk"),
            "max_trurisk": max(r.get("max_trurisk", 0) for r in relevant),
            "avg_qds": avg_f("avg_qds"),
            "total_hosts": avg("total_hosts"),
            "csam_hosts": avg("csam_hosts"),
            "vm_hosts": avg("vm_hosts"),
            "both_hosts": avg("both_hosts"),
            "coverage_pct": avg_f("coverage_pct"),
            "aging_30d": avg("aging_30d"),
            "aging_60d": avg("aging_60d"),
            "aging_90d": avg("aging_90d"),
            "tag_metrics": {},
        })
    return monthly


def seed(reset=False):
    print("=" * 60)
    print("Qualys DA — Seed Data Generator")
    print("=" * 60)

    db = QualysDADatabase()

    if reset:
        print("\nResetting database...")
        tables = [
            "csam_assets", "vm_hosts", "vm_detections", "host_tags",
            "detection_changes", "weekly_rollups", "monthly_rollups",
            "asset_owners", "refresh_log",
        ]
        for t in tables:
            db.conn.execute(f"DELETE FROM {t}")
        db.conn.commit()
        print("  All tables cleared.")

    # ── Generate data ────────────────────────────────────────
    print("\nGenerating hosts...")
    hosts = generate_hosts()
    print(f"  {len(hosts)} hosts generated")

    print("Generating detections...")
    detections = generate_detections(hosts)
    print(f"  {len(detections)} detections generated")

    # Count severity distribution
    sev_counts = {s: 0 for s in range(1, 6)}
    for d in detections:
        sev_counts[d["severity"]] += 1
    total_d = len(detections)
    print("  Severity distribution:")
    for s in range(5, 0, -1):
        pct = sev_counts[s] / total_d * 100
        print(f"    Sev {s}: {sev_counts[s]:>5} ({pct:5.1f}%)")

    # ── Save CSAM assets ─────────────────────────────────────
    print("\nSaving CSAM assets...")
    csam_assets = []
    for h in hosts:
        if not h["in_csam"]:
            continue
        csam_assets.append({
            "assetId": f"CSAM-{h['host_id']}",
            "name": h["hostname"],
            "address": h["ip"],
            "os": h["os"],
            "hardware": {"manufacturer": random.choice(["Dell", "HP", "Lenovo", "VMware"]),
                         "model": random.choice(["PowerEdge R750", "ProLiant DL380", "ThinkSystem SR650", "Virtual Machine"]),
                         "totalMemory": random.choice([8192, 16384, 32768, 65536])},
            "software": h["software"],
            "tagList": [{"tagId": t["id"], "tagName": t["name"], "criticalityScore": t["crit"]} for t in h["tags"]],
            "openPort": [{"port": p, "protocol": "TCP"} for p in random.sample([22, 80, 443, 3306, 5432, 8080, 8443, 9090], k=random.randint(1, 4))],
            "networkInterface": [],
            "lastSeen": random_date(7),
            "created": random_date(365, 180),
        })
    count = db.save_csam_assets(csam_assets, FETCHED_AT)
    print(f"  {count} CSAM assets saved")

    # ── Save VM hosts ────────────────────────────────────────
    print("Saving VM hosts...")
    vm_hosts = []
    for h in hosts:
        if not h["in_vm"]:
            continue
        vm_hosts.append({
            "host_id": h["host_id"],
            "ip": h["ip"],
            "dns": h["dns"],
            "netbios": h["netbios"],
            "os": h["os"],
            "trurisk_score": h["trurisk_score"],
            "last_scan_date": h["last_scan_date"],
            "last_vm_scanned_date": h["last_scan_date"],
            "last_activity_date": random_date(3),
            "tracking_method": h["tracking_method"],
        })
    count = db.save_vm_hosts(vm_hosts, FETCHED_AT)
    print(f"  {count} VM hosts saved")

    # ── Save detections ──────────────────────────────────────
    print("Saving detections...")
    count = db.save_vm_detections(detections, FETCHED_AT)
    print(f"  {count} detections saved")

    # ── Save tags ────────────────────────────────────────────
    print("Saving host tags...")
    tag_records = []
    for h in hosts:
        source = "csam" if h["in_csam"] else "vm"
        for t in h["tags"]:
            tag_records.append({
                "host_id": h["host_id"],
                "ip_address": h["ip"],
                "tag_id": t["id"],
                "tag_name": t["name"],
                "criticality_score": t.get("crit"),
                "source": source,
            })
    count = db.save_host_tags(tag_records, FETCHED_AT)
    print(f"  {count} tag assignments saved")

    # ── Save ownership rules ─────────────────────────────────
    print("Saving ownership rules...")
    now_str = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
    for o in OWNERS:
        try:
            db.add_owner(
                match_type=o["type"],
                match_value=o["value"],
                owner=o["owner"],
                business_unit=o["bu"],
                notes="Seeded by test data generator"
            )
        except Exception:
            pass  # May already exist
    print(f"  {len(OWNERS)} ownership rules saved")

    # ── Save detection changes ───────────────────────────────
    print("Saving detection changes...")
    changes = generate_changes(detections)
    count = db.save_detection_changes(changes)
    print(f"  {count} change log entries saved")

    # ── Save weekly rollups ──────────────────────────────────
    print(f"Saving weekly rollups ({NUM_WEEKS_HISTORY} weeks)...")
    weekly = generate_weekly_rollups(detections, hosts)
    for r in weekly:
        db.save_weekly_rollup(r)
    print(f"  {len(weekly)} weekly rollups saved")

    # ── Save monthly rollups ─────────────────────────────────
    print(f"Saving monthly rollups ({NUM_MONTHS_HISTORY} months)...")
    monthly = generate_monthly_rollups(weekly)
    for r in monthly:
        db.save_monthly_rollup(r)
    print(f"  {len(monthly)} monthly rollups saved")

    # ── Log a fake refresh ───────────────────────────────────
    refresh_id = db.log_refresh("all")
    db.complete_refresh(
        refresh_id,
        csam=len(csam_assets),
        vm_hosts=len(vm_hosts),
        vm_detections=len(detections),
        changes=len(changes),
    )
    print("  Refresh log entry created")

    # ── Summary ──────────────────────────────────────────────
    stats = db.get_db_stats()
    print("\n" + "=" * 60)
    print("SEED COMPLETE — Database Summary")
    print("=" * 60)
    for table, count in stats.items():
        if table.startswith("latest_") or table == "db_size_mb":
            continue
        print(f"  {table:25s} {count:>8,}")
    print(f"  {'db_size_mb':25s} {stats.get('db_size_mb', 0):>8.1f}")
    print(f"\nOpen http://localhost:5000 after running: python app.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed Qualys DA with test data")
    parser.add_argument("--reset", action="store_true", help="Wipe existing data before seeding")
    args = parser.parse_args()
    seed(reset=args.reset)
