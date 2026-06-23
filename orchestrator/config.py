"""Load and validate scan configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Severity ordering, lowest -> highest. `unknown` is resolved to a real level
# via `unknown_severity` before any comparison.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_VALID_FAIL_ON = set(SEVERITY_ORDER) | {"none"}


@dataclass
class Config:
    fail_on: str = "high"
    unknown_severity: str = "medium"
    dedup: bool = True
    scanners: dict = field(default_factory=dict)

    @property
    def enabled_scanners(self) -> set[str]:
        return {name for name, cfg in self.scanners.items()
                if cfg.get("enabled", True)}


def load_config(path: str = "/app/scan-config.yml") -> Config:
    raw = {}
    p = Path(path)
    if p.exists():
        raw = yaml.safe_load(p.read_text()) or {}

    cfg = Config(
        fail_on=str(raw.get("fail_on", "high")).lower(),
        unknown_severity=str(raw.get("unknown_severity", "medium")).lower(),
        dedup=bool(raw.get("dedup", True)),
        scanners=raw.get("scanners", {}) or {},
    )

    # Environment override (set via compose) wins over the file.
    env_fail_on = os.environ.get("FAIL_ON", "").strip().lower()
    if env_fail_on:
        cfg.fail_on = env_fail_on

    if cfg.fail_on not in _VALID_FAIL_ON:
        raise ValueError(
            f"Invalid fail_on={cfg.fail_on!r}; expected one of {sorted(_VALID_FAIL_ON)}"
        )
    if cfg.unknown_severity not in set(SEVERITY_ORDER):
        raise ValueError(
            f"Invalid unknown_severity={cfg.unknown_severity!r}; "
            f"expected one of {SEVERITY_ORDER}"
        )
    return cfg
