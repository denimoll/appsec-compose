# Roadmap

## Shipped (on `develop`, pending the 1.0.0 release)

- **Engines** — Semgrep (SAST), Trivy (SCA/IaC/SBOM), Gitleaks (secrets),
  Checkov (IaC) by default; Grype + OSV-Scanner (SCA), TruffleHog (secrets),
  Hadolint (IaC), Syft (SBOM) opt-in. Several tools per category, aggregated.
- **Cross-tool de-duplication** with CVE↔GHSA alias resolution.
- **Suppressions** (`ignore:` rules) and **baseline / delta** (gate only on new).
- **SBOM** in CycloneDX and SPDX.
- **Offline / air-gapped** mode (`preload.sh`).
- **Supply-chain** — pin scanner images by digest (`pin.sh`), or a digest in a
  tool's `version`.
- **Targets** — repo filesystem, container image (public **and private**
  registries), and **build-from-Dockerfile** (scan the built image).
- **Reports** — native SARIF per tool, `findings.json`, CycloneDX/SPDX SBOM, and
  a self-contained HTML summary (severity cards, category filters, per-finding
  details + advisory links, NEW badges in baseline mode).
- **CI/CD** — GitHub Actions + GitLab templates; GHCR collector-image publish.

## Release: 1.0.0

- [ ] **Validate on a real production project** (gate — must pass before tagging).
- [ ] Merge `develop` → `main`.
- [ ] Tag `v1.0.0` + GitHub Release (triggers the collector image publish to GHCR).

## Multi-project & UI (primary future direction)

A "project" = a named **profile** (a scan-config) applied to a target entity.

- [ ] **Enabling primitives** (each independently useful):
  - [ ] `run.sh --config <path> --baseline <path> --reports <dir>` — decouple
        state from the tool directory.
  - [ ] `COMPOSE_PROJECT_NAME=appsec-<slug>` per run — isolate containers/volumes.
  - [ ] `render-env.py` accepts a config path.
  - [ ] Keep `cache/` (Trivy/Grype/Semgrep DBs) global/shared across projects.
- [ ] **Profiles** — one main profile or several reusable profiles (which
      practices/engines, SBOM formats, policy, etc.).
- [ ] **Projects** — entities with their own name, path/address (repo URL or
      local path) and metadata, each referencing a profile.
- [ ] **Scheduling** — run a project's scan on a **cron** schedule.
- [ ] **Batch** — run many projects; aggregated `reports/index.html` across them.
- [ ] **Minimal UI** — thin backend (e.g. FastAPI/Flask) over `run.sh` to CRUD
      profiles/projects, browse reports, and manage schedules.

## Integrations & extras (backlog)

- [ ] **ASPM/ASOC push** — DefectDojo (API import), DependencyTrack (SBOM upload).
- [ ] Prebuilt collector image consumed by compose (`image:` instead of `build:`).
- [ ] Richer **delta report** in HTML (new/fixed diff beyond the baseline NEW flag).
- [ ] More engines as needed (e.g. KICS).
- [ ] Bump `codeql-action` to v4 before its v3 deprecation (Dec 2026).
