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

import os
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
    "hadolint": ("hadolint/hadolint", "2.12.0-alpine", "HADOLINT"),
    "osv": ("ghcr.io/google/osv-scanner", "v2.4.0", "OSV"),
}

# Registry pack fetched offline by preload.sh; used as a local file when offline.
SEMGREP_ONLINE_RULES = "p/default"
SEMGREP_OFFLINE_RULES = "/cache/semgrep/default.yaml"
TRIVY_OFFLINE_FLAGS = "--skip-db-update --skip-java-db-update --offline-scan"


def _image_ref(repo: str, ver: str) -> str:
    """Build an image ref from a `version` that may be a tag OR a digest.

    `1.97.0`            -> repo:1.97.0
    `sha256:abc...`     -> repo@sha256:abc...
    `@sha256:abc...`    -> repo@sha256:abc...
    """
    ver = ver.strip()
    if ver.startswith("@"):
        return f"{repo}{ver}"
    if ver.startswith("sha256:"):
        return f"{repo}@{ver}"
    return f"{repo}:{ver}"


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

    # Scan target (set by run.sh): a docker-archive tar (build mode), a registry
    # image ref (--image), or the repo filesystem mounted at /code.
    image = os.environ.get("ASS_IMAGE", "").strip()
    tar = os.environ.get("ASS_IMAGE_TAR", "").strip()
    if tar:
        grype_target = syft_target = f"docker-archive:{tar}"
    elif image:
        grype_target = syft_target = image
    else:
        grype_target = syft_target = "dir:/code"

    sbom_on = bool(cfg.get("sbom", True))
    formats = cfg.get("sbom_formats", ["cyclonedx"]) or []
    formats = [str(f).lower() for f in formats]

    def version(name: str, default: str) -> str:
        return str((scanners.get(name) or {}).get("version", default))

    enabled = [n for n, c in scanners.items() if (c or {}).get("enabled", True)]

    env: dict[str, str] = {}
    for tool, (repo, default_ver, prefix) in TOOLS.items():
        ver = version(tool, default_ver)
        # `version` may already be a digest (manual per-tool pin); honour it.
        tagref = _image_ref(repo, ver)
        env[f"{prefix}_VERSION"] = ver
        env[f"{prefix}_TAGREF"] = tagref
        env[f"{prefix}_IMAGE"] = pins.get(tagref, tagref)   # lock digest if pinned

    env.update({
        "SEMGREP_RULES": SEMGREP_OFFLINE_RULES if offline else SEMGREP_ONLINE_RULES,
        "TRIVY_DB_FLAGS": TRIVY_OFFLINE_FLAGS if offline else "",
        "GRYPE_DB_AUTO_UPDATE": "false" if offline else "true",
        # Empty => gitleaks scans git history; default skips it (working tree only).
        "GITLEAKS_GIT_FLAG": "" if cfg.get("secrets_history", False) else "--no-git",
        "ASS_SBOM_CDX": "1" if sbom_on and "cyclonedx" in formats else "0",
        "ASS_SBOM_SPDX": "1" if sbom_on and "spdx" in formats else "0",
        "ASS_IMAGE": image,
        "ASS_IMAGE_TAR": tar,
        "ASS_GRYPE_TARGET": grype_target,
        "ASS_SYFT_TARGET": syft_target,
        "FAIL_ON": str(cfg.get("fail_on", "high")),
        # All tag refs (for ./pin.sh to resolve to digests).
        "ASS_TAGREFS": " ".join(env[f"{p}_TAGREF"] for _, _, p in TOOLS.values()),
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
