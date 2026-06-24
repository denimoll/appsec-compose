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

| Category | Tool | Default | Output |
|---|---|---|---|
| SAST | [Semgrep](https://semgrep.dev) | on | `semgrep.sarif` |
| SCA | [Trivy](https://trivy.dev) | on | `trivy-fs.sarif` |
| SCA (alt) | [Grype](https://github.com/anchore/grype) | off | `grype.sarif` |
| IaC | [Trivy config](https://trivy.dev) | on | `trivy-config.sarif` |
| IaC | [Checkov](https://www.checkov.io) | on | `checkov.sarif` |
| Secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) | on | `gitleaks.sarif` |
| Secrets (alt) | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | off | `trufflehog.json` + `trufflehog.sarif`\* |
| SBOM | [Trivy](https://trivy.dev) | on | `sbom.trivy.cdx.json` |
| SBOM (alt) | [Syft](https://github.com/anchore/syft) | off | `sbom.syft.cdx.json` |

Tools covering the same category are **complementary** — enable one or several;
every enabled tool emits its own native report and all are aggregated.

\* TruffleHog has no native SARIF, so the collector keeps its raw JSON **and**
generates a SARIF from it, so SARIF-only ASPM tools can ingest it too. Our
`findings.json` normalization is internal (for the summary); the per-tool native
reports are what you upload to an ASPM.

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
│   ├── checkov.sarif
│   ├── grype.sarif         # + grype.json (carries CVE/GHSA aliases for dedup)
│   └── trufflehog.json     # + generated trufflehog.sarif
├── findings.json           # consolidated, de-duplicated findings + counts
├── sbom.trivy.cdx.json     # CycloneDX SBOM (Trivy)
├── sbom.syft.cdx.json      # CycloneDX SBOM (Syft, if enabled)
├── summary.md              # human summary
└── summary.html            # human summary (styled)
```

## Policy / exit codes

The **collector** decides pass/fail: exit `1` if any finding is at or above
`fail_on`, else `0`. Scanners themselves always exit `0`, so a noisy finding
never breaks the scan phase — only the policy does. `run.sh` propagates the
collector's exit code, which makes this safe to drop into a CI gate.

## CI/CD

Ready-to-use templates are included:

- **GitHub Actions** — [`.github/workflows/appsec-scan.yml`](.github/workflows/appsec-scan.yml)
  runs the scan, uploads every SARIF to **code scanning**, keeps `reports/` as an
  artifact, caches the vuln DBs, and fails the job on a policy breach.
- **GitLab CI** — [`.gitlab-ci.yml`](.gitlab-ci.yml) runs the scan, exposes the
  CycloneDX SBOM to GitLab Dependency Scanning, and caches DBs. (Needs a runner
  with the host Docker socket — see the file header.)
- **Publish the collector image** — [`.github/workflows/publish-collector.yml`](.github/workflows/publish-collector.yml)
  pushes the collector to GHCR on release, so CI can skip the local build.

## De-duplication

When several tools cover the same category they report the same issues. With
`dedup: true` (default) the collector merges duplicates in `findings.json` and
the summary (the raw native reports are left untouched for ASPM import):

- **secrets** — same `(file, line)` is one secret, regardless of tool.
- **SCA** — same `package@version` + file, clustered by overlapping vuln IDs.
  Trivy's `CVE-2018-1000656` and Grype's `GHSA-562c-5r94-xh97` merge because
  Grype's `relatedVulnerabilities` lists that CVE — so CVE/GHSA aliases collapse.
- **SAST/IaC** — same rule at the same `(file, line)`.

A merged finding keeps the highest severity, records **every tool** that
reported it, and lists the equivalent IDs as aliases. `findings.json` reports
`raw_findings`, `unique_findings` and `duplicates_removed`. Per-tool counts
still reflect each tool's true raw yield.

## Suppressions

Drop known/accepted findings from the gate and counts via an `ignore:` list in
`scan-config.yml`. An entry matches when every field present matches; `rule` is
a glob over the finding's ID **and its aliases** (so a single CVE entry also
catches the equivalent GHSA):

```yaml
ignore:
  - rule: CVE-2018-1000656
    reason: "no fix available, mitigated at the proxy"
  - file: "tests/**"
    reason: "test fixtures"
  - rule: "generic.*"
    category: secrets
    reason: "false positives in sample data"
```

Suppressed findings are excluded from `fail_on` but recorded in `findings.json`
under `suppressed` (with the reason) for the audit trail.

## Baseline (gate on new findings)

Accept the current findings and fail only on **new** ones thereafter:

```bash
# 1. set `baseline: true` in scan-config.yml, then snapshot the accepted state:
./run.sh /path/to/repo --update-baseline      # writes appsec-baseline.json
# 2. commit appsec-baseline.json; subsequent runs gate on new findings only:
./run.sh /path/to/repo
```

Each finding gets a stable fingerprint `(category, id, file, package, line)`.
Runs report `new` / `known` / `fixed` counts (in the console, summary and
`findings.json`), and `fail_on` applies to **new** findings only. Re-run
`--update-baseline` to re-accept the current state.

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
