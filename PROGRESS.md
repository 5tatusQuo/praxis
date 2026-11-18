# PROGRESS

Read this at the start of every session. PLAN.md is the architecture; this file
is the state of the build.

## Current phase

**Phase 2 · Visibility and gaps** — in progress. Phases 0 and 1 passed on 2026-11-18.

## Phase 2 plan

Gate: *coverage snapshot matches a manual audit of one client.*

1. Data map: curated schema notes per log source (`datamap-catalog/`) mapping
   it to ATT&CK data components and the fields each needs.
2. Synthetic telemetry for the fictional clients (`clients/<id>/lab/telemetry.yml`),
   built to exercise every gap class.
3. Read-only collectors on the platform interface: telemetry inventory and
   rule health, using each client's read identity.
4. Gap engine (pure code): visibility score 0–4 per data component, rule
   status, threat weights from sector profiles, one class per technique.
   Rules written down in `docs/visibility-scoring.md`.
5. Coverage snapshots in Postgres, ATT&CK Navigator layer export, snapshot diff.
6. Core services in Compose: Postgres, `praxis-api` (FastAPI), `praxis-web`
   (Next.js dashboard v1: Fleet and client overview).
7. Nightly workflow: top up lab telemetry, snapshot, drift check against
   `packs.lock`, expiry check. CD stores a fresh snapshot after each deploy.
8. Gate run: audit `acme` by hand from raw SIEM queries and compare with the snapshot.

## Done

- **Phase 0 (2026-11-18).** Platform core, Elastic platform, first detections,
  Full-mode stack on the server, CI, CD and a self-hosted runner.
- **Phase 1 (2026-11-18).** Tuning files and platform overlays, exception-list
  rendering, per-client lab checks, `packs.lock`, connection checks, second
  fictional client. See gate evidence below.

## Next

- Phase 2 steps above.

## Decisions

| Date | Decision | Why |
| --- | --- | --- |
| 2026-11-18 | Added the "Elastic first" build rule and a Phase 5 (Splunk + Sentinel) to PLAN.md; Phase 1's gate is now "2 clients on Elastic". | The build brief says Elastic is the only SIEM until Phase 5 and refers to Phases 0–5, but PLAN.md (and its living copy) had Phases 0–4 with Splunk/Sentinel in Phase 1. The living doc on claude.ai was not changed. |
| 2026-11-18 | Until Phase 5, clients are separated on the one bundled Elastic by Kibana space (rules) and data-stream namespace (telemetry). | Gives real multi-tenancy on one free cluster; each client's deploy key only reaches its own space and namespace. |
| 2026-11-18 | Detections name Elastic data-stream patterns ending `-*` in `detection.yml`; the renderer swaps the `*` for the client's namespace. Queries never name indices. | Deterministic per-client index resolution; the lab reuses it with throwaway namespaces, so lab mappings match production. |
| 2026-11-18 | Elastic implementations are EQL (`elastic.eql`) for now; ES\|QL support is added when a detection needs it. | EQL covers the first detections; avoids building an unused path. |
| 2026-11-18 | Envelopes are built as Python dicts, not Jinja templates. | The Kibana envelope is JSON; building it as data is safer than templating text. Revisit for Splunk `.conf` in Phase 5. |
| 2026-11-18 | Content stays in `content/` in this repo for now; its location comes from `praxis.toml` / `PRAXIS_CONTENT_DIR`. | CLAUDE.md rule; lets it move to `praxis-content` later with a settings change only. |
| 2026-11-18 | Licence: Apache-2.0. | PLAN.md's suggested default for adoption. |
| 2026-11-18 | SIEM keys live in files on the self-hosted runner (`/etc/praxis/lab.env`, `/etc/praxis/deploy/<client>.env`), loaded through `PRAXIS_ENV_FILE`. Nothing secret is stored in GitHub. | Matches PLAN.md (deploy creds exist only on the runner) and keeps SIEM credentials off third-party services. Known limit: lab and deploy jobs share one runner user, so a collaborator's pull-request job could read the deploy files; see Open problems. |
| 2026-11-18 | Self-hosted runner jobs are skipped for pull requests from forks, and fork workflows need approval. | The repo is public; fork code must never run on the server. |
| 2026-11-18 | Kibana and Elasticsearch listen on localhost only on the server. | Safe default; reach Kibana through an SSH tunnel (`ssh -L 5601:localhost:5601 <server>`). |
| 2026-11-18 | Fleet Server and Elastic Agent are not deployed yet. | Not needed for the Phase 0 gate; lab telemetry is replayed test events. Revisit in Phase 2 (visibility). |
| 2026-11-18 | Python: code targets 3.12+ (`requires-python`), run through uv. | PLAN.md says 3.12; newer interpreters also work. |
| 2026-11-18 | `packs.lock` is generated in the pull request (`praxis lock`), checked by CI, and enforced by CD; CD no longer commits it back. PLAN.md updated. | `main` is protected, so a CD bot cannot push to it, and a lock reviewed in the PR is a stronger control than one written after the fact. |
| 2026-11-18 | Every `exclude` must carry `examples`: events that fire untuned and stay quiet tuned, replayed in the lab by CI. PLAN.md updated. | Proves a tune does what it claims; together with "positives must still fire" it is the over-tuning guard. |
| 2026-11-18 | Elastic exclusions render to a Kibana exception list per client and rule; the lab applies the same query filter Kibana builds from it. Matching is case-sensitive, as in Kibana. | Analysts see tuning where they expect it. Case sensitivity is a Kibana limit; write exclusions with the casing seen in the evidence. |
| 2026-11-18 | Deferred from Phase 1: `threshold` and `variant` operations (no detection needs them yet), promotion detection (moves to the Tuner in Phase 3), CI routing by changed files (the full run takes under a minute). | Keep the phase to what the gate and current content need. |
| 2026-11-18 | A log source with no events in the last 24 hours scores 0 ("silent"), whatever its history. | A source that stopped sending cannot detect anything now; scoring its history would hide exactly the "rule exists but is blind" problem. |
| 2026-11-18 | Technique visibility is the best score among its data components; visible from 2. Rules and thresholds are in `docs/visibility-scoring.md` and recorded in each snapshot. | Simple, explainable, deterministic. The doc states the limit: visible means some relevant telemetry flows, not that every variant can be seen. |
| 2026-11-18 | Snapshots, including event volumes, live in Postgres. `tables.csv` is produced on demand by `praxis coverage --out`, not committed nightly. | A nightly commit of changing counts to a protected branch is noise. The table list can be committed when it changes; revisit with the schema-note agent in Phase 3. |
| 2026-11-18 | Core services for now: Postgres, API, dashboard. Not yet deployed: MinIO, Redis worker, Keycloak, Gitea. Navigator layers are generated on request from the snapshot. | Nothing needs object storage, a queue or SSO yet. The API uses a bearer token and every port listens on localhost only. Each is added when a feature needs it. |
| 2026-11-18 | The dashboard heatmap is plain SVG/CSS hex cells, without ECharts or Monaco yet. | No chart library is needed for a grid of cells; add libraries when the Tuning studio needs them. |
| 2026-11-18 | Lab telemetry is generated from the sample event in each schema note and marked `labels.praxis_lab: seed`. | One source of truth for what a log source looks like; the marker lets top-ups continue from the last generated event. |

## Open problems

- Runner isolation: lab (pull request) and deploy (main) jobs run as the same user on one runner. Only repo collaborators can start jobs there, but a stricter split (separate runner users or ephemeral runners) is worth doing before any real client is connected.

## Gate evidence

### Phase 0 — a merged PR deploys a tested rule to local ELK (passed 2026-11-18)

- PR: https://github.com/5tatusQuo/praxis/pull/1 added PRX-000002 (shadow copy
  deletion) to the baseline pack.
- CI on the PR, all green: secret scan and workflow lint, code style, unit
  tests, content validation, render, and **lab staging on the self-hosted
  runner** against live Elastic 9.5.5 (4 positive cases fired, 3 negative cases
  stayed quiet).
  https://github.com/5tatusQuo/praxis/actions/runs/44207915125
- Merge to `main` (now a protected branch) triggered CD run
  https://github.com/5tatusQuo/praxis/actions/runs/44208075104, which reported
  `PRX-000001 unchanged`, `PRX-000002 created`, and both smoke checks
  `succeeded` ("Rule execution completed successfully").
- Beyond the gate: replaying the positive test events into the `acme`
  namespace made the deployed rules raise real alerts in the `acme` Kibana
  space: 4 alerts from PRX-000002 and 2 from PRX-000001.

### Phase 1 — one rule, tuned differently for 2 clients, live on Elastic (passed 2026-11-18)

- PR https://github.com/5tatusQuo/praxis/pull/2 added tuning, `packs.lock` and
  the second client; CI green including lab staging of every client's tuning
  (https://github.com/5tatusQuo/praxis/actions/runs/44209609696).
- First deploy (run 44209787575) deployed both clients correctly but **failed
  its smoke check** for `acme`: an updated rule keeps its old schedule, so no
  run completed within the timeout. Fixed in PR
  https://github.com/5tatusQuo/praxis/pull/3 (updated rules are re-enabled so
  they run at once).
- Clean deploy: https://github.com/5tatusQuo/praxis/actions/runs/44210735550.
  PRX-000001 `updated` for both clients, every smoke check `succeeded`.
- PRX-000001 is tuned differently per client: `acme` excludes its imaging
  support agent (exception list `praxis-acme-prx-000001`, wildcard on
  `process.parent.executable`, expires 2027-05-31); `globex` runs it at
  critical severity every minute.
- Live proof: the same event (rundll32 comsvcs MiniDump, parent
  `mdcollect.exe`) was replayed into both namespaces, plus two ordinary
  positives into `acme` as a control. Result in the alert indices:
  `globex` 1 alert, parent `mdcollect.exe`, severity `critical`;
  `acme` 4 alerts, parents `cmd.exe` and `powershell.exe` only, severity
  `high`. The tuned event was suppressed for `acme` while its rule kept firing.
