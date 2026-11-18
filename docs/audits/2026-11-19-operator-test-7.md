# Operator test 7: a whole client life, no workarounds, nothing undocumented

Date: 2026-11-19 · Client: `wrenfold` (fictional building and engineering firm, 65 endpoints, new sector `buildworks`)

A seventh fresh sub-agent ran the same strict task after the fixes from test 6
(PR #83). **Pass.** Its report ends:

```
WORKAROUNDS: 0
UNDOCUMENTED COMMANDS: 0
STEPS NOT COMPLETED OR NOT RUN BY ME: 0
```

It ran no `git`, `gh`, `ssh`, `curl` or `python`, read no repo file other than
`CLAUDE.md` and `docs/runbook.md`, made no hand edits and met no permission
refusals. It used `--help` on twelve commands, which the guides name. It did
not use the MCP tools or the dashboard (see "Not covered" below).

| Step | Outcome | Pull request |
| --- | --- | --- |
| Create the client | Sector `buildworks` with six ATT&CK groups and `T1490=0.3`; client with the `baseline` pack | |
| Connect to the SIEM | Read `ok` ("write correctly refused"), deploy `ok` | |
| Lab telemetry | 11,100 events; logons from 45 of 65 hosts; file events silent for 4 days | |
| Deploy the baseline | PRX-000001 to 000003 `created`, `succeeded`; drift check clean | #84 |
| Coverage | 7 covered, 522 detection gaps, 177 visibility gaps; threat-weighted 3.91%. File components 0 ("11 techniques are not visible because of it"); logon component 3 ("58 techniques rely on it at reduced confidence") | |
| Hand-written detection | PRX-000021, administrative share mounted with `net use` (T1021.002); lab 4 of 4; shadow, then promoted; covered 9, threat-weighted 7.09% | #85, #86 |
| Agent rule pack | `wrenfold-2026.12.0`: one pick (PRX-000022, unexpected child of the Windows DNS service), Reviewer verdict pass on the first proposal, score 84, lab 15 pass; read with `change show --diff`, merged, running in shadow | #87 |
| Noisy rule, then tuning | 29 alerts, 25 from a backup agent; exclusion "removes 25 of 29 matches; 4 remain"; `./px tuning` showed 29 without, 4 with, 25 suppressed | #88 |
| Hunt | Four hypotheses, two durable; the record id got the `-2` suffix because a record with that id already existed | #89 |
| Offboard | 5 rules, 2 keys, space and telemetry removed; "verified in the SIEM: no PRAXIS rules, no active keys, no Kibana space, no telemetry"; kept items listed | #90 |

The sub-agent merged #84 to #90, the agent-opened #87, #88 and #89 under
approvals written into its task. The main session ran nothing for it.

## Independent check

After the run, the main session queried the SIEM directly (read-only): data
namespaces, active PRAXIS keys and Kibana spaces exist for `acme` and `globex`
only, plus the shared lab. GitHub shows #84 to #90 merged and no open pull
requests.

## What test 7 does and does not show about the test 6 fixes

- Hunt id suffix: used live, worked.
- `change show` with no checks yet: seen live, the message was clear.
- Pack planning: the first proposal passed, so the failed-candidate memory and
  the pick-mapping guard were **not** triggered. They remain covered by unit
  tests only.
- `change merge` on an already merged pull request: not triggered.

## Friction it reported, and what was done

| Friction | Action |
| --- | --- |
| Merges took 7 to 13 minutes; the runbook said five to ten | Runbook says seven to fifteen, also for changes that deploy nothing. The time is the lab checks plus one runner; not changed |
| `status` showed an offboarded client's pack as "merged, in shadow" | Shows "record only: its client was offboarded" |
| `detection write` gave no next step | Prints the `lab test` and `detection assign` commands |
| `client add` adds "(fictional)" to the name without saying so | Runbook says so |
| `change status <number>` prints more than checks | Runbook wording corrected |
| Snapshot times are UTC, record dates are local | Runbook says so |
| `attack groups` finds few groups for building and engineering terms | Not changed: ATT&CK has few groups described by those sectors. The runbook already warns |
| The pack proposed one rule for a budget of two | By design: the budget is a ceiling |
| PRX-000022 names a real software vendor in an exclusion path, copied from the upstream Elastic rule | Not changed; for the owner to decide. It is a product path in detection logic, not a client |
| PRX-000022 lists index patterns the client does not send | Not changed; harmless in Elastic, noted |
| A hunt query failed and survives only as a sentence in the assessment | Open: the hunt record should keep failed queries as data |
| Coverage table is wider than a terminal | Not changed: the fixed wide layout is what keeps piped output whole |

The six "Action" changes above were made after the run and checked by the main
session, not by a fresh sub-agent. They change wording and one printed hint;
no command or option was added or renamed.

## Not covered

- The MCP server. A sub-agent's session does not load a project's MCP
  servers, so no sub-agent could use it. The main session tested it over
  stdio (18 tools; `status` and `get_coverage` called).
- The dashboard. The guides say the assistant does not use it.
