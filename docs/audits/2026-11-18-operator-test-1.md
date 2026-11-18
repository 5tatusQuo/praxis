# Operator test 1: a fresh AI session onboards a client

Date: 2026-11-18 · Client: `stonebridge` (fictional, 60 endpoints, sector `construction`)

A sub-agent with no knowledge of PRAXIS beyond the repository was told to
operate PRAXIS for a user and take one new client through its whole life. The
main session played the user and answered only what a user would. The agent
was told to log every point of friction literally.

**Result: all ten steps completed, with two workarounds and a long friction
log.** The sub-agent merged PRs #30 to #35; the three agent-opened ones (#33,
#34, #35) on the approval of the main session acting as the user. One finding was serious. Everything on the list was then fixed in
PRAXIS (pull request #36), and the test was run again with a new agent
(operator test 2).

## What the agent did

| Step | Outcome |
| --- | --- |
| Create the client | Sector `construction` with five ATT&CK groups; client with the `baseline` pack |
| Connect to the SIEM | Read identity `ok` ("write correctly refused"), deploy identity `ok` |
| Lab telemetry | 4,200 process events and 2,100 registry events |
| Deploy the baseline | PR #30; PRX-000001 to 000003 `created`, first runs `succeeded` |
| Coverage | 7 covered, 485 detection gaps, 214 visibility gaps; threat-weighted 4.63% |
| Hand-written detection | PRX-000007 (Defender protection disabled with PowerShell, T1685); 4 of 4 lab cases; PRs #31 and #32; threat-weighted coverage 6.35% |
| Agent rule pack | PR #33: three rules, Reviewer verdict pass; merged on the user's approval, left in shadow |
| Noisy rule, then tuning | 25 benign backup-agent events replayed; Tuner proposed one three-condition exclusion (PR #34); a second replay after the merge raised no new alerts |
| Hunt | PR #35: five hypotheses run read-only; four marked durable |
| Report | Delivered, with the friction log below |

The agent stopped once to ask the user before merging the three agent-opened
pull requests, as CLAUDE.md requires.

## Findings, and what was done about each

| Finding | Fix (PR #36 unless noted) |
| --- | --- |
| **`tune` ran from the pack's `ai/` branch and silently put the whole unapproved rule pack into its own pull request.** Merging it alone would have deployed the pack. | Agent commands refuse to start anywhere but an up-to-date `main`, and return to `main` when they finish |
| A second `./px` command during a merge failed with raw ssh "address already in use" errors | Each run picks free local ports |
| No command to read a pull request, close one, or return to `main`; the agent ran `git switch main` twice | `change show`, `change close`, `change home` |
| `change merge` took about six minutes and printed nothing until the end | Progress lines; a deploy touches only the clients a change affects; a record-only change deploys nothing |
| Every merge redeployed all three clients | Same |
| Nothing said when alerts had arrived; the agent slept and re-ran coverage | `alerts --wait-for` |
| `attack groups` could not find groups by target sector; the agent chose groups from its own knowledge | The search also matches aliases and descriptions; an empty result explains that ransomware families are software in ATT&CK, not groups |
| Runbook said provisioning creates three keys; output said two | Runbook corrected: the lab key is shared, a new client gets two |
| Provisioning printed about 30 lines of Docker output and an orphan-container warning | Quiet restart, orphans removed |
| Runbook said "no sentence over 25 words"; the schema allows other limits per field | Runbook points to `--schema` for each field's limits |
| Runbook did not say where to keep the spec file, or the format of the replay events file | Both documented; `change submit` only takes files under `content/` |
| Coverage said "covered 7" against 4 techniques in the rules table | The output and the runbook explain that a rule on a sub-technique also covers its parent |
| Tables were truncated and wrapped when piped | A fixed wide layout when output is not a terminal; `coverage --summary` |
| `status` showed a promoted pack as "proposed" | A pack's state comes from Git; CD syncs it to the dashboard's database |
| The Tuner did not print the measured impact | It prints it, and the exclusion in plain words |
| A merged tuning still said "awaiting human approval" | Author is `ai:tuner`; approval is the merge |
| The lab profile only held the sources the rules read, so visibility was narrow | `lab source` adds, shapes or removes sources |
| The hunt's next-step text named a command that is not how PRAXIS is run | Corrected |
| MCP tools were not loaded in the sub-agent's session | Not a PRAXIS fault: sub-agents do not load a project's MCP servers. The server was tested separately over stdio through `./px mcp` (18 tools; `status` and `get_coverage` called) |
| The client's name, chosen by the user, might coincide with a real firm | The client was offboarded after the test; the second test uses a plainly invented name |

## Workarounds the agent needed

Two: it ran `git switch main` twice, because no PRAXIS command returned to
`main`. It also read content files and ran read-only `git` commands to
understand what had happened, which is not a workaround but showed the same gap.

## After the test

`stonebridge` was offboarded with `./px client offboard --yes --delete-space
--delete-data`, and its content removed in PR #37.
