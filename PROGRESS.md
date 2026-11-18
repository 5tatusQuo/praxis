# PROGRESS

Read this at the start of every session. PLAN.md is the architecture; this file
is the state of the build.

## Current phase

**Phase 1 · Multi-client core** — in progress. Phase 0 passed on 2026-11-18.

## Phase 1 plan

Gate: *one rule, tuned differently for 2 clients, live on Elastic.*

1. Tuning files (`clients/<id>/tuning/<rule>.yml`) and platform overlays
   (`overlays/platform/<siem>/<rule>.yml`) with the closed set of operations:
   `exclude`, `severity`, `risk_score`, `schedule`, `enabled: false`.
   (`threshold` and `variant` wait for a detection that needs them.)
2. Overlay resolver: native query, then platform overlay, then client tuning.
3. Elastic render of tuning: exclusions become a per-client exception list
   attached to the rule; the other operations change the envelope.
4. Lab tests per client render: positives must still fire under each client's
   tuning (over-tuning guard), and each tuning's example events must fire
   without the tuning and stay quiet with it.
5. `packs.lock` per client: the exact version and hash of every rendered rule.
   CI checks it is current; CD refuses to deploy anything the lock does not pin.
6. Connect mode for Elastic: `praxis connection check <client>` proves the
   read and deploy identities work against a registered SIEM.
7. Second fictional client (`globex`), provisioned in its own space and
   namespace, and one rule tuned differently for each client.
8. Gate run: merge, CD deploys both, the same event alerts for one client and
   is suppressed for the other.

## Done

- **Phase 0 (2026-11-18).** Platform core, Elastic platform, first detections,
  Full-mode stack on the server, CI, CD and a self-hosted runner. See gate
  evidence below.

## Next

- Phase 1 steps above.

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
