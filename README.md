# appsec-compose

One-command, OSS AppSec static scan for any code repository. Runs **SAST, SCA,
secret scanning and IaC** checks via proven open-source engines, then collects
the results into native reports plus a human-readable summary and a CycloneDX
SBOM — ready to read yourself or upload to an ASPM/ASOC (DefectDojo,
DependencyTrack, …).

It is a **thin, stateless orchestrator**: no database, no web UI, no workers.
Each scanner runs as a one-shot Docker Compose service; a small Python collector
aggregates the reports and produces a CI-meaningful exit code.

## Engines

| Category | Tool | Output |
|---|---|---|
| SAST | [Semgrep](https://semgrep.dev) | `semgrep.sarif` |
| SCA + secrets (fs) | [Trivy](https://trivy.dev) | `trivy-fs.sarif` |
| IaC | [Trivy config](https://trivy.dev) | `trivy-config.sarif` |
| SBOM | [Trivy](https://trivy.dev) | `sbom.cdx.json` (CycloneDX) |
| Secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) | `gitleaks.sarif` |
| IaC | [Checkov](https://www.checkov.io) | `checkov.sarif` |

## Usage

```bash
./run.sh /path/to/your/repo
# default fails (exit 1) on high+ findings; override per run:
./run.sh /path/to/your/repo --fail-on critical
```

## Configuration — one file

Everything lives in [`scan-config.yml`](scan-config.yml): which checks run, the
pinned tool **versions** (bump here to upgrade), the policy gate and the offline
switch. `run.sh` renders it into `.env` (which Compose loads) and runs only the
enabled scanners.

```yaml
scanners:
  semgrep:  { enabled: true, version: "1.97.0" }    # SAST
  trivy:    { enabled: true, version: "0.58.0" }     # SCA + IaC + SBOM
  gitleaks: { enabled: true, version: "v8.21.2" }    # secrets
  checkov:  { enabled: true, version: "3.2.334" }    # IaC

sbom: true                 # CycloneDX SBOM via Trivy
fail_on: high              # critical|high|medium|low|none (none = report-only)
unknown_severity: medium
offline: false             # use ./preload.sh cache, no network during scan
```

Disable a check by setting `enabled: false` — that scanner won't run and the
collector won't expect its report. Upgrade a tool by changing its `version`.

## Offline / air-gapped

Run once **with** network to snapshot DBs and rulesets into `./cache/`:

```bash
./preload.sh           # Semgrep ruleset + Trivy vulnerability DB
```

Then set `offline: true` in `scan-config.yml`. Scans now run with no network
access (Semgrep uses the cached ruleset; Trivy uses the cached DB with
`--skip-db-update --offline-scan`). Gitleaks and Checkov bundle their rules in
the image, so they need no preload.

> JVM note: Trivy's Java DB downloads on demand. To scan JVM projects offline,
> run one JVM scan online first to populate `cache/trivy`.

## Output (`./reports/`)

```
reports/
├── native/                 # raw per-tool reports (SARIF) — feed these to ASPM
│   ├── semgrep.sarif
│   ├── trivy-fs.sarif
│   ├── trivy-config.sarif
│   ├── gitleaks.sarif
│   └── checkov.sarif
├── findings.json           # consolidated normalized findings + counts
├── sbom.cdx.json           # CycloneDX SBOM (for DependencyTrack etc.)
├── summary.md              # human summary
└── summary.html            # human summary (styled)
```

## Policy / exit codes

The **collector** decides pass/fail: exit `1` if any finding is at or above
`fail_on`, else `0`. Scanners themselves always exit `0`, so a noisy finding
never breaks the scan phase — only the policy does. `run.sh` propagates the
collector's exit code, which makes this safe to drop into a CI gate.

## How it works

1. `run.sh` renders `scan-config.yml` → `.env` and bind-mounts the target repo
   **read-only** at `/code`.
2. The enabled scanner services run once (in parallel), each writing a native
   SARIF report into the shared `reports/` volume and exiting `0`.
3. `collector` normalizes every SARIF into one model, writes `findings.json` +
   summaries, and exits with the policy code.

No `docker.sock`, no docker-in-docker.

## Layout

```
docker-compose.yml      # scanners + collector (versions/flags from .env)
run.sh                  # entrypoint: render config, run scanners + collector
preload.sh              # offline cache populator
scan-config.yml         # the single file you edit
scripts/render-env.py   # scan-config.yml -> .env
orchestrator/           # Python collector (config, normalize, policy, summary)
```
