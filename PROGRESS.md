# PROGRESS

Read this at the start of every session. PLAN.md is the architecture; this file
is the state of the build.

## Current phase

**Phase 0 · Foundations** — in progress.

## Phase 0 plan

Gate: *a merged PR deploys a tested rule to local ELK.*

1. Repo scaffolding: Python package, settings, schemas for `detection.yml`,
   content packs and clients, README template lint, bundled ATT&CK matrix.
2. Platform interface (`praxis.platforms.Platform`) with Elastic as the first
   implementation: static checks, render to a Kibana rule, lab test, deploy,
   smoke check, client provisioning.
3. First native Elastic detection with docs, positive and negative test events.
4. Full mode on the server: Elasticsearch + Kibana in Docker Compose, TLS and
   security on, random passwords generated on the server.
5. CI (`praxis-ci.yml`): secret scan, workflow lint, code style, unit tests,
   content validation, render, then lab staging on the self-hosted runner.
6. CD (`praxis-cd.yml`): on merge to main, deploy each client's rules through
   the Kibana Detection Engine API from the self-hosted runner and smoke-check.
7. Gate run: a PR that adds a detection, CI green, merge, CD deploys it, the
   rule fires on a replayed positive event.

## Done

- Steps 1–4 built and proven by hand against the live stack (Elastic 9.5.5,
  basic licence): lab test passes 2 positive / 2 negative cases for PRX-000001;
  a manual `praxis release acme` created the rule in the `acme` Kibana space
  and its first run succeeded.

## Next

- Push to GitHub, install the self-hosted runner, wire secrets, run the gate.

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

## Open problems

- Runner isolation: lab (pull request) and deploy (main) jobs run as the same user on one runner. Only repo collaborators can start jobs there, but a stricter split (separate runner users or ephemeral runners) is worth doing before any real client is connected.

## Gate evidence

(none yet)
