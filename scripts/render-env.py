#!/usr/bin/env python3
"""Render scan-config.yml into a Docker Compose .env file.

Single source of truth = scan-config.yml. This writes `.env` (which Compose
loads automatically) with the resolved scanner image refs and the online/offline
behaviour flags, and prints a few shell-evalable lines for run.sh to consume:

    ASS_ENABLED='semgrep trivy gitleaks checkov'
    ASS_OFFLINE=0

Image pinning: if image-digests.lock maps a tool's `repo:tag` to a
`repo@sha256:...` digest (written by ./pin.sh), the resolved <TOOL>_IMAGE uses
the digest; otherwise it uses the plain tag. <TOOL>_TAGREF always holds the tag
form (consumed by pin.sh).
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
LOCK = ROOT / "image-digests.lock"

# tool -> (docker repo, default version, env-var prefix)
TOOLS = {
    "semgrep": ("semgrep/semgrep", "1.97.0", "SEMGREP"),
    "trivy": ("aquasec/trivy", "0.58.0", "TRIVY"),
    "gitleaks": ("zricethezav/gitleaks", "v8.21.2", "GITLEAKS"),
    "checkov": ("bridgecrew/checkov", "3.2.334", "CHECKOV"),
    "grype": ("anchore/grype", "v0.85.0", "GRYPE"),
    "trufflehog": ("trufflesecurity/trufflehog", "3.88.0", "TRUFFLEHOG"),
    "syft": ("anchore/syft", "v1.18.0", "SYFT"),
}

# Registry pack fetched offline by preload.sh; used as a local file when offline.
SEMGREP_ONLINE_RULES = "p/default"
SEMGREP_OFFLINE_RULES = "/cache/semgrep/default.yaml"
TRIVY_OFFLINE_FLAGS = "--skip-db-update --skip-java-db-update --offline-scan"


def _load_lock() -> dict[str, str]:
    """Map `repo:tag` -> `repo@sha256:...` from image-digests.lock."""
    pins: dict[str, str] = {}
    if LOCK.exists():
        for line in LOCK.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tag, _, digest = line.partition(" ")
            if tag and digest:
                pins[tag] = digest.strip()
    return pins


def main() -> int:
    cfg = yaml.safe_load(CFG.read_text()) or {}
    scanners = cfg.get("scanners", {}) or {}
    offline = bool(cfg.get("offline", False))
    pins = _load_lock()

    def version(name: str, default: str) -> str:
        return str((scanners.get(name) or {}).get("version", default))

    enabled = [n for n, c in scanners.items() if (c or {}).get("enabled", True)]

    env: dict[str, str] = {}
    for tool, (repo, default_ver, prefix) in TOOLS.items():
        tagref = f"{repo}:{version(tool, default_ver)}"
        env[f"{prefix}_VERSION"] = version(tool, default_ver)
        env[f"{prefix}_TAGREF"] = tagref
        env[f"{prefix}_IMAGE"] = pins.get(tagref, tagref)   # digest if pinned

    env.update({
        "SEMGREP_RULES": SEMGREP_OFFLINE_RULES if offline else SEMGREP_ONLINE_RULES,
        "TRIVY_DB_FLAGS": TRIVY_OFFLINE_FLAGS if offline else "",
        "GRYPE_DB_AUTO_UPDATE": "false" if offline else "true",
        "ASS_SBOM": "1" if cfg.get("sbom", True) else "0",
        "FAIL_ON": str(cfg.get("fail_on", "high")),
    })

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
