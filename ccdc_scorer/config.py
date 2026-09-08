from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping

from .models import AppConfig, ServiceConfig
from .presets import PresetRegistry, deep_merge


class ConfigError(ValueError):
    pass


ENV_PATTERN = re.compile(r"^\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}$")
CORE_KEYS = {"id", "name", "team", "type", "host", "port", "weight", "timeout", "enabled", "preset", "options"}
DEFAULT_PORTS = {
    "HTTP": 80,
    "HTTPS": 443,
    "DNS": 53,
    "SMTP": 25,
    "POP3": 110,
    "IMAP": 143,
    "FTP": 21,
    "SSH": 22,
    "LDAP": 389,
    "RDP": 3389,
    "SMB": 445,
}
SUPPORTED_TYPES = set(DEFAULT_PORTS) | {"TCP"}


def _expand_env(value: Any, location: str) -> Any:
    if isinstance(value, str):
        match = ENV_PATTERN.match(value)
        if not match:
            return value
        variable = match.group(1)
        if variable not in os.environ:
            raise ConfigError("%s references unset environment variable %s" % (location, variable))
        return os.environ[variable]
    if isinstance(value, list):
        return [_expand_env(item, "%s[]" % location) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env(item, "%s.%s" % (location, key)) for key, item in value.items()}
    return value


def _service_from_raw(
    raw: Mapping[str, Any],
    index: int,
    registry: PresetRegistry,
    default_timeout: float,
) -> ServiceConfig:
    location = "services[%d]" % index
    if not isinstance(raw, Mapping):
        raise ConfigError("%s must be an object" % location)

    preset_name = raw.get("preset")
    resolved: Dict[str, Any] = {}
    if preset_name:
        try:
            resolved = registry.resolve(str(preset_name))
        except (KeyError, ValueError) as exc:
            raise ConfigError("%s: %s" % (location, exc)) from exc
    merged = deep_merge(resolved, raw)
    merged = _expand_env(merged, location)

    missing = [key for key in ("id", "team", "type", "host") if not merged.get(key)]
    if missing:
        raise ConfigError("%s is missing required field(s): %s" % (location, ", ".join(missing)))

    service_type = str(merged["type"]).upper()
    if service_type not in SUPPORTED_TYPES:
        raise ConfigError("%s.type %r is not supported" % (location, service_type))

    port_value = merged.get("port", DEFAULT_PORTS.get(service_type))
    if port_value is None:
        raise ConfigError("%s.port is required for %s" % (location, service_type))
    try:
        port = int(port_value)
        weight = int(merged.get("weight", 10))
        timeout = float(merged.get("timeout", default_timeout))
    except (TypeError, ValueError) as exc:
        raise ConfigError("%s has a non-numeric port, weight, or timeout" % location) from exc
    if not 1 <= port <= 65535:
        raise ConfigError("%s.port must be between 1 and 65535" % location)
    if weight < 0:
        raise ConfigError("%s.weight cannot be negative" % location)
    if timeout <= 0:
        raise ConfigError("%s.timeout must be greater than zero" % location)

    # Flat legacy checker fields remain supported. New configurations can put
    # these values under "options" for a cleaner separation.
    options = dict(merged.get("options") or {})
    for key, value in merged.items():
        if key not in CORE_KEYS:
            options[key] = value

    # Normalize legacy TLS option names.
    if service_type == "SMTP":
        if merged.get("ssl_only"):
            options["tls_mode"] = "implicit"
        elif merged.get("use_tls"):
            options["tls_mode"] = "starttls"
    elif service_type == "POP3" and merged.get("pop_ssl"):
        options["tls_mode"] = "implicit"
    elif service_type == "FTP" and merged.get("ftp_mode"):
        legacy_mode = str(merged["ftp_mode"]).lower()
        options["tls_mode"] = {"explicit_tls": "starttls", "implicit_tls": "implicit"}.get(legacy_mode, legacy_mode)

    # Normalize legacy protocol-specific credential names.
    credential_aliases = {
        "pop_user": "username",
        "pop_pass": "password",
        "ftp_user": "username",
        "ftp_pass": "password",
    }
    for old, new in credential_aliases.items():
        if old in merged and merged.get(old) is not None:
            options[new] = merged[old]

    return ServiceConfig(
        id=str(merged["id"]),
        name=str(merged["name"]) if merged.get("name") else None,
        team=str(merged["team"]),
        type=service_type,
        host=str(merged["host"]),
        port=port,
        weight=weight,
        timeout=timeout,
        enabled=bool(merged.get("enabled", True)),
        preset=str(preset_name) if preset_name else None,
        options=options,
    )


def parse_config(data: Mapping[str, Any], source_path: Path | None = None) -> AppConfig:
    if not isinstance(data, Mapping):
        raise ConfigError("Configuration root must be an object")
    try:
        default_timeout = float(data.get("timeout_seconds", 6.0))
        interval = float(data.get("interval_seconds", 60.0))
        max_workers = int(data.get("max_workers", 16))
        history_limit = int(data.get("history_limit", 50))
    except (TypeError, ValueError) as exc:
        raise ConfigError("Engine timing and worker settings must be numeric") from exc
    if default_timeout <= 0 or interval <= 0 or max_workers <= 0 or history_limit <= 0:
        raise ConfigError("Timeout, interval, workers, and history limit must be greater than zero")

    custom_presets = data.get("presets") or {}
    if not isinstance(custom_presets, Mapping):
        raise ConfigError("presets must be an object")
    registry = PresetRegistry(custom_presets)
    raw_services = data.get("services") or []
    if not isinstance(raw_services, list) or not raw_services:
        raise ConfigError("services must be a non-empty array")
    services = [
        _service_from_raw(raw, index, registry, default_timeout)
        for index, raw in enumerate(raw_services)
    ]
    ids = [service.id for service in services]
    duplicates = sorted({service_id for service_id in ids if ids.count(service_id) > 1})
    if duplicates:
        raise ConfigError("Service IDs must be unique; duplicates: %s" % ", ".join(duplicates))
    matrix_cells: Dict[tuple[str, str], str] = {}
    for service in services:
        matrix_key = str(service.option("matrix_key") or service.display_name).strip()
        if not matrix_key:
            raise ConfigError("Service %s has an empty matrix_key" % service.id)
        token = (service.team.casefold(), matrix_key.casefold())
        if token in matrix_cells:
            raise ConfigError(
                "Services %s and %s occupy the same team/matrix_key cell; use unique matrix_key values"
                % (matrix_cells[token], service.id)
            )
        matrix_cells[token] = service.id
        try:
            int(service.option("matrix_order", 0))
        except (TypeError, ValueError) as exc:
            raise ConfigError("Service %s has a non-numeric matrix_order" % service.id) from exc

    baseline_mode = str(data.get("baseline_mode", "learn")).lower()
    if baseline_mode not in {"learn", "disabled"}:
        raise ConfigError("baseline_mode must be 'learn' or 'disabled'")
    return AppConfig(
        services=services,
        interval_seconds=interval,
        timeout_seconds=default_timeout,
        max_workers=max_workers,
        history_limit=history_limit,
        baseline_mode=baseline_mode,
        score_first_success=bool(data.get("score_first_success", True)),
        database_name=str(data.get("database_name", "scoring.db")),
        source_path=source_path,
        custom_presets={str(key): dict(value) for key, value in custom_presets.items()},
    )


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).expanduser().resolve()
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError("Configuration file not found: %s" % config_path) from exc
    except json.JSONDecodeError as exc:
        raise ConfigError("Invalid JSON in %s at line %d: %s" % (config_path, exc.lineno, exc.msg)) from exc
    return parse_config(data, source_path=config_path)
