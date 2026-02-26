"""Configuration loading and validation.

Loads settings from a YAML file with environment variable overrides.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger(__name__)


@dataclass
class QRadarConfig:
    url: str = ""
    api_token: str = ""
    verify_ssl: bool = True
    timeout: int = 120


@dataclass
class MISPConfig:
    url: str = ""
    api_key: str = ""
    verify_ssl: bool = True
    distribution: int = 0
    auto_publish: bool = False
    tags: list[str] = field(default_factory=lambda: ["qradar", "automated-import", "tlp:amber"])


@dataclass
class PollerConfig:
    interval_seconds: int = 300
    min_magnitude: int = 3
    max_offenses_per_cycle: int = 50
    offense_filter_categories: list[str] = field(default_factory=list)  # empty = all


@dataclass
class EnrichmentConfig:
    enabled: bool = True
    time_window: str = "24 HOURS"
    max_results_per_query: int = 100
    aql_timeout: int = 120


@dataclass
class SightingConfig:
    enabled: bool = True
    interval_seconds: int = 3600
    misp_lookback: str = "30d"
    qradar_lookback: str = "24 HOURS"
    source_name: str = "QRadar"


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: str = ""
    max_bytes: int = 10_485_760  # 10MB
    backup_count: int = 5


@dataclass
class AppConfig:
    qradar: QRadarConfig = field(default_factory=QRadarConfig)
    misp: MISPConfig = field(default_factory=MISPConfig)
    poller: PollerConfig = field(default_factory=PollerConfig)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)
    sighting: SightingConfig = field(default_factory=SightingConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    state_file: str = "/var/lib/qradar-misp-sync/state.json"


def _apply_env_overrides(config: AppConfig):
    """Override config values with environment variables if set."""
    env_map = {
        "QRADAR_URL": ("qradar", "url"),
        "QRADAR_TOKEN": ("qradar", "api_token"),
        "QRADAR_VERIFY_SSL": ("qradar", "verify_ssl"),
        "MISP_URL": ("misp", "url"),
        "MISP_KEY": ("misp", "api_key"),
        "MISP_VERIFY_SSL": ("misp", "verify_ssl"),
        "MISP_DISTRIBUTION": ("misp", "distribution"),
        "MISP_AUTO_PUBLISH": ("misp", "auto_publish"),
        "POLL_INTERVAL": ("poller", "interval_seconds"),
        "MIN_MAGNITUDE": ("poller", "min_magnitude"),
        "STATE_FILE": (None, "state_file"),
    }

    for env_var, path in env_map.items():
        value = os.environ.get(env_var)
        if value is None:
            continue

        section_name, field_name = path
        if section_name:
            section = getattr(config, section_name)
        else:
            section = config

        current = getattr(section, field_name)
        if isinstance(current, bool):
            setattr(section, field_name, value.lower() in ("true", "1", "yes"))
        elif isinstance(current, int):
            setattr(section, field_name, int(value))
        else:
            setattr(section, field_name, value)

        log.debug("Config override from env: %s", env_var)


def _dict_to_dataclass(data: dict, cls):
    """Recursively convert a dict to a dataclass instance."""
    field_names = {f.name for f in cls.__dataclass_fields__.values()}
    filtered = {}
    for key, value in data.items():
        if key in field_names:
            field_type = cls.__dataclass_fields__[key].type
            # Check if the field is itself a dataclass
            if hasattr(field_type, "__dataclass_fields__") and isinstance(value, dict):
                filtered[key] = _dict_to_dataclass(value, field_type)
            else:
                filtered[key] = value
    return cls(**filtered)


def load_config(config_path: str) -> AppConfig:
    """Load configuration from a YAML file with env var overrides.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Validated AppConfig.

    Raises:
        FileNotFoundError: If the config file doesn't exist.
        ValueError: If required fields are missing.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(path, "r") as f:
        raw = yaml.safe_load(f) or {}

    # Build config from YAML
    config = AppConfig()

    if "qradar" in raw:
        config.qradar = _dict_to_dataclass(raw["qradar"], QRadarConfig)
    if "misp" in raw:
        config.misp = _dict_to_dataclass(raw["misp"], MISPConfig)
    if "poller" in raw:
        config.poller = _dict_to_dataclass(raw["poller"], PollerConfig)
    if "enrichment" in raw:
        config.enrichment = _dict_to_dataclass(raw["enrichment"], EnrichmentConfig)
    if "sighting" in raw:
        config.sighting = _dict_to_dataclass(raw["sighting"], SightingConfig)
    if "logging" in raw:
        config.logging = _dict_to_dataclass(raw["logging"], LoggingConfig)
    if "state_file" in raw:
        config.state_file = raw["state_file"]

    # Apply environment variable overrides
    _apply_env_overrides(config)

    # Validate required fields
    errors = []
    if not config.qradar.url:
        errors.append("qradar.url is required")
    if not config.qradar.api_token:
        errors.append("qradar.api_token is required")
    if not config.misp.url:
        errors.append("misp.url is required")
    if not config.misp.api_key:
        errors.append("misp.api_key is required")

    if errors:
        raise ValueError("Configuration errors:\n  - " + "\n  - ".join(errors))

    return config
