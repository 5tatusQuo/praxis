# PROGRESS

Read this at the start of every session. PLAN.md is the architecture; this file
is the state of the build.

## Current phase

**Between Phase 4 and Phase 5.** All gates for Phases 0 to 4 passed on
2026-11-18 and v1.0.0 is released. Phase 5 does not start until the PLAN.md
items listed under "Not built yet" below are done.

## Operator test: PRAXIS driven by an AI (passed on the fifth run, 2026-11-19)

Goal set by the owner: make PRAXIS fully operable by an AI agent with no
rough spots, and prove it with a fresh sub-agent that takes a new fictional
client through its whole life using only documented commands.

Each run used a new sub-agent with no knowledge beyond the repo, and a new
client. Reports, with every finding and its fix, are in `docs/audits/`.

| Run | Client | Result | Report |
| --- | --- | --- | --- |
| 1 | `stonebridge` | 10 steps; 2 workarounds (`git switch main` twice); one serious finding (a tuning proposal carried an unapproved pack) | `2026-11-18-operator-test-1.md` |
| 2 | `vantmoor` | 11 steps; 0 workarounds; 5 commands run by the main session because the sub-agent's session refused relayed approvals | `2026-11-18-operator-test-2.md` |
| 3 | `brindlewick` | 11 steps by the agent alone; 0 workarounds; but it used read-only `git` three times to read pull requests. Not a pass | `2026-11-18-operator-test-3.md` |
| 4 | `harlowmere` | 0 workarounds, no `git`; the Reviewer failed the pack so it never ran in shadow; 11 undocumented read-only commands (per-command help, `detection list`). Not a pass | `2026-11-18-operator-test-4.md` |
| 5 | `pellwick` (building and engineering) | **All 11 steps by the agent alone. `WORKAROUNDS: 0`, `UNDOCUMENTED COMMANDS: 1`, `STEPS NOT COMPLETED OR NOT RUN BY ME: 0`** | `2026-11-19-operator-test-5.md` |

The one undocumented command in run 5 was `./px change status <number>`, a
read-only form the agent found through the documented `./px change --help`.
The runbook now names it. That one-line addition has not been through a
further run.

Pull requests:

- Platform: #29 (operator commands, `./px`, MCP server, runbook), #36 (fixes
  from run 1), #38 (dashboard sign-in), #46 (run 2), #54 (run 3), #62 (run 4),
  and this change (run 5 and the evidence). All merged by the main session.
- Run 1: #30 to #35 merged by the sub-agent, the agent-opened #33, #34, #35
  on the main session's approval as the user; #37 (offboarding) by the main
  session.
- Run 2: #39 to #42 merged by the sub-agent; #43 (tuning), #44 (hunt) and
  #45 (offboarding) merged by the main session as the user.
- Run 3: #47 to #53 merged by the sub-agent under approvals in its task.
- Run 4: #55 to #57 and #59 to #61 merged by the sub-agent; #58 (failed pack)
  closed by the main session.
- Run 5: #63 to #65 and #67 to #70 merged by the sub-agent; #66 (failed pack)
  closed by the sub-agent.

What an operator reads: `CLAUDE.md`, then `docs/runbook.md`. Every step is a
`./px` command; the same actions are MCP tools (`.mcp.json`).

Checked outside the sub-agent runs: the MCP server over stdio through
`./px mcp` (18 tools listed; `status` and `get_coverage` called). A
sub-agent does not load a project's MCP servers, so the runs used `./px`.
After runs 3 and 5, a direct read-only query of the SIEM showed data, keys
and Kibana spaces for `acme` and `globex` only.

Still open from the test:

- Runbook limits that could not be fixed here, each stated there with its
  reason: lab telemetry is synthetic (no Fleet Server or Elastic Agent in the
  stack); one SIEM connection (no second SIEM here to test against); Elastic
  and EQL only (other SIEMs are Phase 5); an offboarded client cannot be
  re-checked later; no command removes a sector profile or a pack record.
- The Reviewer agent is not consistent: in run 5 it failed a pack for a query
  construct and passed the next proposal with the same construct
  (PRX-000019, staged, runs nowhere). Review it before promoting.
- The Curator does not propose assigning a detection the library already has.
- Agent wording can lag the facts ("before you merge" notes; hunt summaries).
  Numbers come from code.
- A merge takes five to ten minutes, by design.
- The tests left detections that no client runs (PRX-000008 to 000019),
  five sector profiles, and pack and hunt records. Keeping, assigning or
  deprecating them is the owner's decision.

## Not built yet (PLAN.md items inside Phases 0–4)

The gates passed without these. They are owed before Phase 5 starts.
Suggested order, most important first:

1. **Tenancy in the database**: row-level security in Postgres. (Dashboard
   sign-in with Keycloak, an administrator role and per-client roles is built;
   the API itself still trusts one bearer token held by the dashboard.)
2. **Agent runs on the server**: a worker with a queue, "request a pack / hunt /
   tuning" from the dashboard, a GitHub App or token to open pull requests,
   and the per-run container sandbox. Today agents run from a workstation.
3. **Pull-request report from CI**: a bot comment with the coverage diff per
   client, backtest table and Navigator layer; CI routing by changed files;
   the `quality-waiver` label for low scores.
4. **Drift handling**: nightly drift is detected and fails the job; it does not
   yet open a pull request or revert a console edit.
5. **Remaining agents**: CTI Analyst (report to detection opportunities), the
   schema-note drafter for unknown tables, existing-rule triage for adoption.
6. **Tuning operations**: `threshold` and `variant`; ES|QL implementations.
7. **Client reporting**: the month-end report; alert closure reasons from a
   ticketing system.
8. **CLI and UI parity**: `praxis client add`, `praxis chat`, in-browser agent
   chat in the Tuning studio, Monaco, the Rule library and detection grid views.
9. **Hardening**: pre-commit installed by default, SOPS for secrets, cosign
   image signing, signed commits on content, runner isolation.
10. **Full mode extras**: Fleet Server and Elastic Agent, optional lab
    endpoints with Atomic Red Team, MinIO, optional Gitea.

## Phase 3 plan

Gate: *first AI-curated pack merged after human review.*

1. Candidate catalog: pinned upstream sources (`content/sources.yml`), Sigma
   ingest, pySigma first-draft queries, logic fingerprints, Postgres full-text search.
2. Deterministic quality scorer: specificity, Pyramid of Pain tier, durability,
   upstream maturity, overlap with the library, backtest volume.
3. Read-only backtests and alert statistics on the platform interface, with
   redaction (allow-listed fields, pseudonymised users and hosts).
4. One tool registry (`praxis.agents.toolbox`) used by the in-process agents
   and served over MCP (`praxis mcp`).
5. Agents on Claude (Anthropic SDK): Curator, Platform Engineer (Elastic),
   Reviewer, Tuner. Guardrails enforced in code: budget, diversity, duplicates,
   indicator-tier rules, licence, "must close a current gap".
6. `praxis pack plan` and `praxis tune`: work on an `ai/` branch, open a pull
   request with a report; proposals and the audit trail stored in Postgres.
7. Shadow mode: `staged` detections deploy at the lowest severity with a
   `praxis-shadow` tag until a promotion PR.
8. Dashboard: Rule packs, Pack review, Tuning studio (live impact preview), Audit.
9. Gate run: the Curator proposes a pack for `acme`, CI passes, you review and merge.

## Phase 4 status

Proven with the real model on 2026-11-18 (`gpt-6.1-sol` on the owner's ChatGPT plan):

- **Hunt Planner**: PR #17. It looked the group up in ATT&CK, wrote hypotheses
  with native queries and ran each read-only against `acme`. Hit counts in the
  record come from the queries code ran.
- **Tuner**: PR #22, on the third attempt. The first two runs exposed faults in
  the tuning tool, not just the model:
  1. Four conditions meant to apply together were stored as four alternative
     exclusions; one alone would have silenced the rule. Closed unmerged (#18).
     Fixed in #19: conditions under `also`, and the tool now refuses
     pseudonymised values, bad expiry dates and uncited evidence.
  2. The backtest capped every count at 5, so the Tuner was told its exclusion
     removed almost nothing. Closed unmerged (#20). Fixed in #21.

- **Agent proposals merged by the owner**: the tuning (#22) and the hunt
  record (#17).
- **First pack promoted** (#25, on the owner's say-so, the same day it was
  staged; the 14-day shadow period was not observed). `praxis pack promote`
  (#24) replaces the hand edit. Checked in Kibana: the three rules carry their
  own severity and no shadow tag. `acme` went from 5 to 11 covered techniques
  and from 3.1% to 9.58% threat-weighted coverage.

The demo video is deferred to the very end, by the owner's decision.

## Phase 4 groundwork (built earlier)

Gate: *v1.0 public release on GitHub.* Not attempted: v1.0 should not be
tagged before the Phase 3 gate has really passed.

Built and checked without a model:

- **Hunt Planner** (`praxis hunt`), hunt records in `content/hunts/`, the
  `attack_group` and `run_hunt_query` tools, Hunts pages in the dashboard.
  Tested with the scripted model only; hit counts in a hunt record come from
  the queries code actually ran.
- **Brand**: the Praxis lens mark, app icon, CLI banner, `docs/brand`.
- **Docs**: `docs/deploying.md`, `docs/agents.md`.
- **Helm chart** (`deploy/helm/praxis`) and **Terraform for AWS**
  (`deploy/terraform/aws`), written early. Both pass lint and validate in CI.
  Proving them on real infrastructure now belongs to Phase 5.
- **Release workflow**: a version tag builds and publishes both images to
  GitHub Container Registry with SBOM and provenance, then creates the release.
  It has never run.

Not done: the demo video (needs a person and a screen recording), cosign
signatures, and signed commits on the content repo.

## Blocked on you

Nothing right now.

Decided by you on 2026-11-18: cloud work (Helm, Terraform), the other SIEMs
and the demo video come last, in Phase 5, and Phase 5 waits until Phases 0–4
are completely done. You approved tagging v1.0 and promoting the first pack.

## Done

- **Phase 0 (2026-11-18).** Platform core, Elastic platform, first detections,
  Full-mode stack on the server, CI, CD and a self-hosted runner.
- **Phase 1 (2026-11-18).** Tuning files and platform overlays, exception-list
  rendering, per-client lab checks, `packs.lock`, connection checks, second
  fictional client.
- **Phase 2 (2026-11-18).** Data map, lab telemetry, read-only collectors, gap
  engine, snapshots, Navigator layers, API, dashboard v1, nightly workflow.
- **Phase 3, everything that needs no model (2026-11-18).** Steps 1 to 8 above.
  Proven live: 2,075 upstream rules ingested at pinned commits (1,683 SigmaHQ,
  392 Elastic EQL; 2,005 with a first-draft Elastic query) and stored in the
  server's Postgres; the MCP
  server answers `tools/list` and `tools/call` over stdio; the Tuning studio
  preview measured a real exclusion for `globex` (1 of 1 match suppressed over
  30 days, both positive tests still fire, example silenced). Proven in unit
  tests with a scripted model: the whole Curator → guardrails → Engineer →
  Reviewer flow, every guardrail, and the Tuner.

## Next

- The "Not built yet" list above.
- Phase 5, only after Phases 0–4 are completely done: Splunk and Sentinel, then cloud deployment.

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
| 2026-11-18 | Agents run on the Claude Messages API with a loop PRAXIS hosts (default model `claude-opus-5-5`, set by `PRAXIS_LLM_MODEL`), not Claude Managed Agents. | The tools must reach SIEMs that only listen on the server's network, and PLAN.md has agents run in your own sandbox. Managed Agents would move the loop and tool execution to Anthropic's side. |
| 2026-11-18 | Requests opt in to server-side refusal fallbacks (`fallbacks: "default"`). | If a safety classifier declines a security-flavoured request, the API retries it on another model instead of failing the whole pack run. Remove it in `agents/llm.py` if you do not want that. |
| 2026-11-18 | Guardrails, scores, backtests and lab results in a pack are computed by code after the agents answer. A Reviewer `blocker` fails the pack whatever verdict it wrote. | "Deterministic first, AI second": a model cannot talk its way past the budget or report its own test results. |
| 2026-11-18 | Agents run from a workstation through `deploy/with-server.sh` (SSH tunnels, lab and read keys passed in the environment only) and open the PR with your own GitHub login. | A PR opened by the Actions bot does not trigger CI, and the server has no GitHub credentials. No deploy key is ever fetched. The container sandbox per agent run in PLAN.md is not built yet; see Open problems. |
| 2026-11-18 | Catalog search is Postgres full-text plus technique filters. No vector index yet. | Embeddings need a second provider or a local model; full-text and ATT&CK ids are enough to find candidates. pgvector is in the image for when it is wanted. |
| 2026-11-18 | SigmaHQ is ingested under DRL 1.1 (redistribution with attribution; author, id and commit kept in provenance and `reference/sigma.yml`). `sources.yml` has a `redistribute` switch per source. | Superseded in part the same day: see the Elastic `detection-rules` row below. |
| 2026-11-18 | Tuning studio v1 is a deterministic preview (alerts, rendered rule, override editor, live impact). The Tuner agent is driven from the CLI (`praxis tune`), and proposing from the browser is not wired. Monaco is not used yet. | The preview is the part that needs no secret in the browser path. Opening PRs from the web needs a GitHub App or token on the server, which is your call. |
| 2026-11-18 | The API container gets lab and read keys only (`/opt/praxis/api.env`); deploy keys stay with the runner. CD mirrors `content/` to `/var/lib/praxis/content` for the API. | Keeps "no service but CD can deploy" true while the studio can backtest and replay. |
| 2026-11-18 | `external_llm: false` in `client.yml` stops every agent for that client. | PLAN.md's per-client switch for data minimisation. |
| 2026-11-18 | (Superseded the same day by Sign in with ChatGPT, below.) Claude can authenticate with an OAuth profile from `ant auth login` or an API key. | Kept as the fallback provider. |
| 2026-11-18 | Cloud deployment moved from Phase 4 to Phase 5, with Splunk and Sentinel; Phase 5 starts only when Phases 0–4 are completely done. PLAN.md updated. | Your decision. The Helm chart and Terraform module already written stay in the repo, lint-checked but unproven, until then. |
| 2026-11-18 | Elastic `detection-rules` is ingested (EQL rules under `rules/windows`, pinned commit, `redistribute: true`); Splunk ESCU will be ingested with the Splunk platform in Phase 5. | You approved ingesting and redistributing both. ESCU is SPL, which no platform can draft or test until Phase 5. Derived detections keep licence, rule id and commit in provenance. |
| 2026-11-18 | The agents' model credential is "Sign in with ChatGPT" from the dashboard (OpenAI's plan-usage flow for open-source, self-hosted apps); the agents then run on OpenAI's Responses API. Claude via `ant auth login` or an API key remains as the fallback provider (`PRAXIS_LLM_PROVIDER`). | Your decision: a dashboard login is what a user expects, and Anthropic offers no OAuth flow a web app can use. PLAN.md already calls for a swappable provider. |
| 2026-11-18 | The sign-in returns to the dashboard's own `/auth/callback` on `http://127.0.0.1:<port>`, reached through the SSH tunnel (`deploy/dashboard.sh`). | OpenAI's flow only allows a 127.0.0.1 loopback redirect. Their documented route for a remote server is "sign in locally, copy the credential file over SSH"; serving the callback through the tunnel reaches the same result without copying tokens by hand. It is not a setup their docs describe, so it may need revisiting. |
| 2026-11-18 | Tokens live in one mode-600 file in the API container's own volume, not in Postgres. The API hands a short-lived access token (never the refresh token) to an operator's agent run over the tunnel. | Follows OpenAI's storage rules (protected self-hosted storage, atomic writes, serialised refresh). The token endpoint exists because agents still run on the workstation; it goes away when agent runs move to the server. |
| 2026-11-18 | With OpenAI, the final answer comes back through a `submit_answer` function tool, and requests send `store: false`, `stream: true` and the full history each turn. | The preview's documented rules. Its docs do not say whether JSON-schema structured output is supported, so the provider does not depend on it. |
| 2026-11-18 | Agent text follows the ASD-STE100 writing rules and fixed templates with word limits. Code rejects answers over a word or sentence limit; the pull-request report is one table plus short lists. Limits are listed in `docs/agents.md`. | Your review of the first pack: too much text for a person to read, and it repeated numbers the page already shows. Only sentence length and word counts are checked by code; the STE dictionary is not applied. |
| 2026-11-18 | A shadow (staged) rule gives no coverage until it is promoted; snapshots report it under its own status. | The first pack's three shadow rules were being counted as covered techniques, which overstated coverage: their alerts do not reach the SOC. |
| 2026-11-18 | An exclusion can carry more conditions under `also` that must all match; separate exclusions stay alternatives. | The Tuner needs a way to say "all of these together". Without it, narrowing an exclusion widened it. |
| 2026-11-18 | Backtests count up to 1000 matches and report when they hit that cap. | An EQL search only counts what it returns; the old limit of 5 made every count wrong above 5. Earlier pack backtests reported 0, which was unaffected. |
| 2026-11-18 | The demo video moves to the very end (after Phase 5's SIEM and cloud work). PLAN.md updated. | Your decision. |
| 2026-11-18 | The first pack was promoted the day it was staged. | Your decision. The usual 14 days in shadow exist to catch noise on live data; the lab's telemetry is synthetic, so little would have been learned by waiting. |
| 2026-11-18 | Dashboard sign-in is Keycloak, served under the dashboard's own address (`/kc`), with a hand-written OpenID Connect flow in the dashboard rather than an auth library. Roles: `praxis-admin` sees everything; `client:<id>` sees that client. | One address means the browser and the dashboard's server agree on the issuer and no second port is tunnelled. The auth library's stable release does not support this Next.js version. Keycloak runs in dev mode on its embedded database, which is fine for one local server and not for production. |

## Open problems

- The dashboard now requires sign-in, but the API behind it still accepts one shared bearer token, and Keycloak runs in dev mode with its embedded database. Access control is enforced in the dashboard, not in the API or the database.
- OpenAI's plan-usage preview: the exact request shape for function tools is not in the docs I could read. The provider sends plain function tools and falls back to a namespace wrapper if they are refused; expect adjustments on first contact. One ChatGPT account funds every agent run, whoever starts it.
- Agent sandbox: PLAN.md calls for each agent run in a container with no network except the MCP server and the LLM endpoint. Today agents run as a normal process on the operator's workstation. Their tools are allow-listed per role and none can deploy, but the process itself is not confined.
- The Tuner's own notes can lag the fixes: a model's wording describes what its tools told it. Numbers in a pull request come from code, so trust those over the prose.
- Fingerprint overlap is approximate (it ignores boolean structure) and did not flag the SigmaHQ rules closest to PRX-000001 and PRX-000002 as duplicates. The Curator also sees the library by technique, and the Reviewer checks overlap, but the automatic check should be tightened.
- The pySigma first drafts use `.caseless` sub-fields and `any where`, which PRAXIS rewrites; drafts are starting points and the Engineer agent is expected to rewrite them.
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

### Phase 2 — coverage snapshot matches a manual audit of one client (passed 2026-11-18)

- PR https://github.com/5tatusQuo/praxis/pull/4; CD run
  https://github.com/5tatusQuo/praxis/actions/runs/44213526191 deployed
  PRX-000003 to both clients and stored snapshots 3 (acme) and 4 (globex).
- Audit of `acme`: `docs/audits/2026-11-18-phase-2-acme.md`. An independent
  script (`docs/audits/audit-client.sh`: raw `curl` to Elasticsearch and
  Kibana, rules applied in `jq`, no code shared with the engine) reproduced
  the snapshot exactly: 6 of 6 component scores, 3 of 3 rule statuses, and
  the class of 706 of 706 techniques (5 covered, 2 blind rule, 527 detection
  gap, 172 visibility gap).
- The lab scenario came out as designed: registry source silent, so
  PRX-000003 is a blind rule for `acme` and healthy for `globex`.
- Nightly workflow run by hand,
  https://github.com/5tatusQuo/praxis/actions/runs/44213800359: telemetry
  top-up, snapshots 5 and 6 stored, drift check "the SIEM matches packs.lock"
  for both clients, expiry check clean.
- Dashboard checked in a headless browser against the live API: Fleet and
  client overview render the snapshot (heatmap, gaps, silent-source warning).
- Limit: the audit was scripted by the same author as the engine. The raw
  facts table in the audit document is small enough to check by eye.

### Phase 3 — first AI-curated pack merged after human review (passed 2026-11-18)

- Sign in with ChatGPT completed by the owner in the dashboard; plan usage
  granted; agents ran on `gpt-6.1-sol`. The first real model call needed no
  change to the tool-calling format.
- `praxis pack plan acme --month 2026-12 --budget 3` produced
  https://github.com/5tatusQuo/praxis/pull/11: three staged detections written
  by the Platform Engineer agent from SigmaHQ candidates the Curator picked
  (PRX-000004 service registry deletion via reg.exe, T1685; PRX-000005 RDP
  registry configuration via reg.exe, T1021.001; PRX-000006 PowerShell TCP
  stream, T1059.001). 42 lab cases pass; each scores 94; 0 backtest hits on
  lab telemetry, which is synthetic and benign.
- Found by the run: the scorer counted each new rule as a duplicate of itself
  (the Reviewer agent flagged it; fixed in PR #12 and the pack re-measured by
  code). The owner's review led to the short writing template (PR #13) and
  rule names in reports (PR #15); the pack text was rewritten to the template
  by the Curator and reviewed again from scratch (verdict: pass, no comments).
- **Merged by the owner** (5tatusQuo) at 2026-11-18T05:30:56Z, after review.
- CD run https://github.com/5tatusQuo/praxis/actions/runs/44244796737 created
  the three rules in the `acme` Kibana space. Checked in Kibana: each is
  enabled, named `[shadow] …`, severity low, tagged `praxis-shadow`, last run
  succeeded.
- Not yet done for this pack: the 14-day shadow period and the promotion PR.

### Phase 4 — v1.0 public release on GitHub (passed 2026-11-18)

- Owner's go-ahead given on 2026-11-18 to tag v1.0 and to promote the first pack.
- Hunt Planner and Tuner proven with the real model; their proposals (#17,
  #22) merged by the owner. First pack promoted (#25).
- Release PR https://github.com/5tatusQuo/praxis/pull/26 set the version to
  1.0.0. Tag `v1.0.0` pushed; release workflow run
  https://github.com/5tatusQuo/praxis/actions/runs/44255330662 succeeded on
  its first run: both images built and published, release created.
- Release: https://github.com/5tatusQuo/praxis/releases/tag/v1.0.0
- Images pulled anonymously from the deployment server to confirm they are
  public: `ghcr.io/5tatusquo/praxis-api:v1.0.0`, `ghcr.io/5tatusquo/praxis-web:v1.0.0`.
- What v1.0 is not: it has run only with fictional clients on synthetic lab
  telemetry, on one server, with Elastic. See "Not built yet" above.
