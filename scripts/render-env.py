#!/usr/bin/env python3
"""Render scan-config.yml into a Docker Compose .env file.

Single source of truth = scan-config.yml. This writes `.env` (which Compose
loads automatically) with image versions and the online/offline behaviour
flags, and prints a few shell-evalable lines for run.sh to consume:

    ASS_ENABLED='semgrep trivy gitleaks checkov'
    ASS_OFFLINE=0
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required on the host: pip3 install pyyaml")

ROOT = Path(__file__).resolve().parent.parent
CFG = ROOT / "scan-config.yml"

# Registry pack fetched offline by preload.sh; used as a local file when offline.
SEMGREP_ONLINE_RULES = "p/default"
SEMGREP_OFFLINE_RULES = "/cache/semgrep/default.yaml"
TRIVY_OFFLINE_FLAGS = "--skip-db-update --skip-java-db-update --offline-scan"


def main() -> int:
    cfg = yaml.safe_load(CFG.read_text()) or {}
    scanners = cfg.get("scanners", {}) or {}
    offline = bool(cfg.get("offline", False))

    def version(name: str, default: str) -> str:
        return str((scanners.get(name) or {}).get("version", default))

    enabled = [n for n, c in scanners.items() if (c or {}).get("enabled", True)]

    env = {
        "SEMGREP_VERSION": version("semgrep", "1.97.0"),
        "TRIVY_VERSION": version("trivy", "0.58.0"),
        "GITLEAKS_VERSION": version("gitleaks", "v8.21.2"),
        "CHECKOV_VERSION": version("checkov", "3.2.334"),
        "SEMGREP_RULES": SEMGREP_OFFLINE_RULES if offline else SEMGREP_ONLINE_RULES,
        "TRIVY_DB_FLAGS": TRIVY_OFFLINE_FLAGS if offline else "",
        "ASS_SBOM": "1" if cfg.get("sbom", True) else "0",
        "FAIL_ON": str(cfg.get("fail_on", "high")),
    }

    (ROOT / ".env").write_text(
        "# Generated from scan-config.yml by scripts/render-env.py — do not edit.\n"
        + "".join(f"{k}={v}\n" for k, v in env.items())
    )

    # Shell-consumable summary for run.sh.
    print(f"ASS_ENABLED='{' '.join(enabled)}'")
    print(f"ASS_OFFLINE={'1' if offline else '0'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
