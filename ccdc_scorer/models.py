from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


@dataclasses.dataclass(frozen=True)
class ServiceConfig:
    id: str
    team: str
    type: str
    host: str
    port: int
    weight: int = 10
    timeout: float = 6.0
    enabled: bool = True
    name: Optional[str] = None
    preset: Optional[str] = None
    options: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def option(self, name: str, default: Any = None) -> Any:
        return self.options.get(name, default)

    @property
    def display_name(self) -> str:
        return self.name or self.id

    def public_dict(self) -> Dict[str, Any]:
        """Return fields safe for the unauthenticated scoreboard API."""
        return {
            "id": self.id,
            "name": self.display_name,
            "team": self.team,
            "type": self.type,
            "host": self.host,
            "port": self.port,
            "weight": self.weight,
            "enabled": self.enabled,
            "preset": self.preset,
        }


@dataclasses.dataclass(frozen=True)
class CheckOutcome:
    passed: bool
    message: str
    latency_ms: Optional[int]
    fingerprint: Optional[str]
    details: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ServiceResult:
    id: str
    team: str
    type: str
    host: str
    port: int
    passed: bool
    accurate: Optional[bool]
    points: int
    message: str
    latency_ms: Optional[int]
    fingerprint: Optional[str]
    timestamp: str
    baseline_state: str = "pending"
    details: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def as_dict(self, include_fingerprint: bool = False) -> Dict[str, Any]:
        payload = dataclasses.asdict(self)
        if not include_fingerprint:
            payload.pop("fingerprint", None)
        return payload


@dataclasses.dataclass(frozen=True)
class RoundRecord:
    number: int
    started_at: str
    finished_at: str
    results: Sequence[ServiceResult]
    totals: Dict[str, int]


@dataclasses.dataclass(frozen=True)
class AppConfig:
    services: List[ServiceConfig]
    interval_seconds: float = 60.0
    timeout_seconds: float = 6.0
    max_workers: int = 16
    history_limit: int = 50
    baseline_mode: str = "learn"
    score_first_success: bool = True
    database_name: str = "scoring.db"
    source_path: Optional[Path] = None
    custom_presets: Dict[str, Dict[str, Any]] = dataclasses.field(default_factory=dict)

    @property
    def enabled_services(self) -> List[ServiceConfig]:
        return [service for service in self.services if service.enabled]
