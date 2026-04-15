"""
Configuration Loader

Securely loads settings from config/.config with environment variable overrides.
Credentials are masked in all output.
"""

import os
import stat
import logging
import warnings
from pathlib import Path
from configparser import ConfigParser
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class QualysDAConfig:
    """Configuration container with masked credentials."""

    # API
    vm_base_url: str = "https://qualysapi.qualys.eu"
    csam_base_url: str = "https://gateway.qg1.apps.qualys.eu"
    timeout: int = 60
    max_retries: int = 3

    # Credentials
    username: str = ""
    password: str = ""

    # Rate limiting
    rate_limit_enabled: bool = True
    calls_per_minute: int = 60

    # Refresh
    parallel_refresh: bool = True   # Pull VM and CSAM in parallel (~40-50% faster)
    csam_page_size: int = 1000      # Assets per CSAM call (max 1000). 104k assets
                                    # → 104 calls at 1000, vs 347 calls at 300.
    csam_lookback_days: int = 90    # Server-side QQL filter on 'lastCheckedIn'.
                                    # 0 = no filter (pull everything).
    csam_resume_enabled: bool = True  # Resume from last asset ID if a prior pull
                                      # was interrupted (rate-limit / crash).

    # Database
    db_path: str = "data/qualys_da.db"

    # Retention (GFS)
    daily_retention_days: int = 30
    weekly_retention_weeks: int = 52

    # Analytics
    trend_window_weeks: int = 12

    # Tags
    monitored_tags: List[str] = field(default_factory=list)

    # SLA (days per severity)
    sla_severity_5: int = 7
    sla_severity_4: int = 30
    sla_severity_3: int = 90
    sla_severity_2: int = 180
    sla_severity_1: int = 365

    # Ownership
    ownership_import_file: str = ""

    # Scheduler
    scheduler_enabled: bool = True
    refresh_day: str = "monday"
    refresh_hour: int = 6

    # Server (Flask bind host + port)
    server_host: str = "localhost"
    server_port: int = 5001

    # Logging
    log_level: str = "INFO"

    def __repr__(self) -> str:
        return (
            f"QualysDAConfig(vm_url='{self.vm_base_url}', "
            f"csam_url='{self.csam_base_url}', "
            f"username='{'*' * len(self.username) if self.username else '<NOT SET>'}', "
            f"password='{'*' * 8 if self.password else '<NOT SET>'}')"
        )

    def is_configured(self) -> bool:
        return bool(self.username and self.password and self.vm_base_url)

    def validate(self) -> List[str]:
        issues = []
        if not self.vm_base_url:
            issues.append("VM API URL required")
        if not self.csam_base_url:
            issues.append("CSAM API URL required")
        if not self.username:
            issues.append("Username required (config or QUALYS_DA_USERNAME env)")
        if not self.password:
            issues.append("Password required (config or QUALYS_DA_PASSWORD env)")
        if self.vm_base_url and not self.vm_base_url.startswith("https://"):
            issues.append("VM API URL must use HTTPS")
        if self.csam_base_url and not self.csam_base_url.startswith("https://"):
            issues.append("CSAM API URL must use HTTPS")
        return issues

    def get_sla_days(self, severity: int) -> int:
        """Get SLA window in days for a given severity level."""
        return {
            5: self.sla_severity_5,
            4: self.sla_severity_4,
            3: self.sla_severity_3,
            2: self.sla_severity_2,
            1: self.sla_severity_1,
        }.get(severity, 365)


def check_file_permissions(filepath: Path) -> None:
    """Warn if config file has insecure permissions."""
    if not filepath.exists():
        return

    # Skip on Windows (no chmod concept)
    if os.name == "nt":
        return

    mode = filepath.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        warnings.warn(
            f"\nConfig '{filepath}' is readable by others.\n"
            f"   Run: chmod 600 {filepath}\n",
            SecurityWarning,
            stacklevel=3,
        )


def load_config(config_path: Optional[Path] = None) -> QualysDAConfig:
    """
    Load configuration from file and environment.

    Priority: Environment variables > config file > defaults
    """
    # Find config directory
    if config_path:
        config_dir = config_path.parent
        config_file = config_path
    else:
        config_dir = Path(__file__).parent.parent / "config"
        config_file = config_dir / ".config"

    parser = ConfigParser()

    # Load example for defaults
    example = config_dir / ".config.example"
    if example.exists():
        parser.read(example)

    # Load user config
    if config_file.exists():
        check_file_permissions(config_file)
        parser.read(config_file)
    else:
        logger.warning(f"Config not found: {config_file}")

    def get_str(sec: str, key: str, default: str = "") -> str:
        """Get string value, stripping whitespace and surrounding quotes."""
        value = parser.get(sec, key, fallback=default).strip()
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        return value

    def get_int(sec: str, key: str, default: int) -> int:
        try:
            return parser.getint(sec, key, fallback=default)
        except ValueError:
            return default

    def get_bool(sec: str, key: str, default: bool) -> bool:
        try:
            return parser.getboolean(sec, key, fallback=default)
        except ValueError:
            return default

    # Parse monitored tags
    tags_str = get_str("tags", "monitored_tags", "")
    monitored_tags = [t.strip() for t in tags_str.split(",") if t.strip()]

    config = QualysDAConfig(
        vm_base_url=get_str("api", "vm_base_url", "https://qualysapi.qualys.eu"),
        csam_base_url=get_str("api", "csam_base_url", "https://gateway.qg1.apps.qualys.eu"),
        timeout=get_int("api", "timeout", 60),
        max_retries=get_int("api", "max_retries", 3),
        username=get_str("credentials", "username", ""),
        password=get_str("credentials", "password", ""),
        rate_limit_enabled=get_bool("rate_limit", "enabled", True),
        calls_per_minute=get_int("rate_limit", "calls_per_minute", 60),
        parallel_refresh=get_bool("api", "parallel_refresh", True),
        csam_page_size=get_int("api", "csam_page_size", 1000),
        csam_lookback_days=get_int("api", "csam_lookback_days", 90),
        csam_resume_enabled=get_bool("api", "csam_resume_enabled", True),
        db_path=get_str("database", "db_path", "data/qualys_da.db"),
        daily_retention_days=get_int("retention", "daily_retention_days", 30),
        weekly_retention_weeks=get_int("retention", "weekly_retention_weeks", 52),
        trend_window_weeks=get_int("analytics", "trend_window_weeks", 12),
        monitored_tags=monitored_tags,
        sla_severity_5=get_int("sla", "severity_5", 7),
        sla_severity_4=get_int("sla", "severity_4", 30),
        sla_severity_3=get_int("sla", "severity_3", 90),
        sla_severity_2=get_int("sla", "severity_2", 180),
        sla_severity_1=get_int("sla", "severity_1", 365),
        ownership_import_file=get_str("ownership", "import_file", ""),
        scheduler_enabled=get_bool("scheduler", "enabled", True),
        refresh_day=get_str("scheduler", "refresh_day", "monday"),
        refresh_hour=get_int("scheduler", "refresh_hour", 6),
        server_host=get_str("server", "host", "localhost"),
        server_port=get_int("server", "port", 5001),
        log_level=get_str("logging", "level", "INFO"),
    )

    # Environment overrides
    env_map = {
        "QUALYS_DA_USERNAME": ("username", str),
        "QUALYS_DA_PASSWORD": ("password", str),
        "QUALYS_DA_VM_URL": ("vm_base_url", str),
        "QUALYS_DA_CSAM_URL": ("csam_base_url", str),
        "QUALYS_DA_TIMEOUT": ("timeout", int),
        "QUALYS_DA_HOST": ("server_host", str),
        "QUALYS_DA_PORT": ("server_port", int),
    }

    for env_var, (attr, converter) in env_map.items():
        value = os.environ.get(env_var)
        if value:
            setattr(config, attr, converter(value))

    return config


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    config = load_config()
    print(config)
    issues = config.validate()
    for issue in issues:
        print(f"  - {issue}")
