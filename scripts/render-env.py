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

# Local drop-in rules dir (mounted into the semgrep container at /semgrep-rules).
SEMGREP_RULES_DIR = "semgrep-rules"

# Stack auto-detect: file extension / name -> Semgrep registry pack.
_EXT_PACKS = {
    ".py": "p/python", ".js": "p/javascript", ".jsx": "p/javascript",
    ".ts": "p/typescript", ".tsx": "p/typescript", ".go": "p/golang",
    ".java": "p/java", ".rb": "p/ruby", ".php": "p/php", ".cs": "p/csharp",
    ".kt": "p/kotlin", ".scala": "p/scala", ".rs": "p/rust", ".tf": "p/terraform",
}
_NAME_PACKS = {"dockerfile": "p/dockerfile"}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv",
              "venv", "__pycache__", ".idea", ".gradle", "target"}


def _autodetect_packs() -> list[str]:
    """Detect the repo's stack and map it to Semgrep registry packs."""
    target = os.environ.get("SCAN_TARGET", "")
    if not target or not Path(target).is_dir():
        return []
    packs: list[str] = []
    seen = set()
    scanned = 0
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            scanned += 1
            pack = _NAME_PACKS.get(fn.lower()) or _EXT_PACKS.get(Path(fn).suffix.lower())
            if pack and pack not in seen:
                seen.add(pack)
                packs.append(pack)
        if scanned > 20000 or len(seen) == len(set(_EXT_PACKS.values()) | set(_NAME_PACKS.values())):
            break
    return packs


def _semgrep_configs(scanners: dict, offline: bool) -> str:
    """Build the `--config ...` argument string for semgrep from scan-config."""
    default = SEMGREP_OFFLINE_RULES if offline else SEMGREP_ONLINE_RULES
    rules = (scanners.get("semgrep") or {}).get("rules", None)

    configs: list[str] = []
    if rules is None:
        configs.append(default)                 # default behaviour
    else:
        for r in rules:
            r = str(r).strip()
            if r == "default":
                configs.append(default)
            elif r == "auto":
                configs.extend(_autodetect_packs() if not offline else [default])
            elif r:
                configs.append(r)               # registry ref or container path

    # Local drop-in rules, if any rule files (*.yml/*.yaml) are present.
    rules_dir = ROOT / SEMGREP_RULES_DIR
    if rules_dir.is_dir() and (any(rules_dir.rglob("*.yml")) or any(rules_dir.rglob("*.yaml"))):
        configs.append("/semgrep-rules")

    # De-duplicate (preserve order); never end up with nothing.
    seen, ordered = set(), []
    for c in configs:
        if c and c not in seen:
            seen.add(c)
            ordered.append(c)
    if not ordered:
        ordered.append(default)

    return " ".join(f"--config {c}" for c in ordered)


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
        "SEMGREP_CONFIGS": _semgrep_configs(scanners, offline),
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
