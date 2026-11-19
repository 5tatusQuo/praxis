# Operator test 11: an unassisted pass on the current product

Date: 2026-11-19 · Client: `halverstone` (fictional building and engineering firm, 40 endpoints, new sector `civilworks`)

An eleventh fresh sub-agent ran the strict task on `main` after PR #119. Before
the run the owner asked for a Claude Code permission rule that allows
`./px change merge`, because the sub-agents' sessions in tests 8 to 10 had
refused their first merge of an agent-opened pull request. The rule is in the
project's local settings file, which is not in Git.

**Pass.** The report ends:

```
WORKAROUNDS: 0
UNDOCUMENTED COMMANDS: 0
STEPS NOT COMPLETED OR NOT RUN BY ME: 0
```

It ran no `git`, `gh`, `ssh`, `curl` or `python`, read no repo file other than
the two guides, met no permission refusal, and ran every step itself. The main
session ran nothing for it. The whole client life took about 28 minutes.

| Step | Outcome | Pull request |
| --- | --- | --- |
| Create the client | Six groups from eight lookups; sector `civilworks`; client with the `baseline` pack | |
| Connect to the SIEM | Read `ok` ("write correctly refused"), deploy `ok` | |
| Lab telemetry | 11,100 events; logons from 28 of 40 hosts; file events silent for 4 days | |
| Deploy the baseline | PRX-000001 to 000003 `created`, `succeeded`; drift check clean | #120 |
| Coverage | 7 covered, 522 detection gaps, 177 visibility gaps; threat-weighted 3.21% | |
| Hand-written detection | PRX-000032, domain controllers or computers enumerated with nltest or dsquery (T1018); `detection write` listed PRX-000012 as already on the technique; lab 4 of 4; shadow, then promoted; threat-weighted 4.82% | #121, #122 |
| Agent rule pack | One pick (PRX-000033, winget installation from a local manifest), Reviewer verdict pass on the first proposal, score 88, lab 11 pass; read in full, merged by the sub-agent, running in shadow | #123 |
| Noisy rule, then tuning | 29 alerts, 25 from a backup agent; one exclusion, "removes 25 of 29 matches; 4 remain"; `./px tuning` showed 29 without, 4 with, 25 suppressed | #124 |
| Hunt | Five hypotheses, two durable; three refused queries recorded under `failed_queries`, each re-run in a form the SIEM accepts | #125 |
| Offboard | 5 rules, 2 keys, space and telemetry removed; "verified in the SIEM: no PRAXIS rules, no active keys, no Kibana space, no telemetry"; then `sector remove`, `pack remove`, `hunt-remove` | #126 |

The sub-agent merged #120 to #126, the agent-opened #123, #124 and #125 under
approvals written into its task.

## Independent check

After the run the main session queried the SIEM directly (read-only): data,
active PRAXIS keys and Kibana spaces exist for `acme` and `globex` only. No
pull request is open. Sectors are `finance` and `healthcare`.

## What this run covers

Every change made after test 7 that a run can reach: failed hunt queries as
data, the group lookup, the three remove commands, the faster lab check, the
`detection write` overlap note, the options table in the runbook, and the
tuning proposal with no redundant exclusion (one exclusion was written).

Not reached, because no run can force them: the pack retry path (the first
proposal passed again) and the "too broad" mark on a hunt query.

## Friction reported, each with what it is

No product change was made after this run.

| Friction | What it is |
| --- | --- |
| Coverage gives the cost of a partial or silent source as a count of techniques, not as a change in the visible percentage | By design: the count is exact; the percentage would need a second scoring pass with the source assumed healthy. Recorded as an idea |
| The pack held one rule for a budget of two, and does not say why | Open. The budget is a ceiling, which the runbook says; the pack record should say why it stopped at one |
| The pick is generic, not specific to the sector | Agent judgement. The Reviewer passed it and the owner merges or closes |
| Grammar in a pull request body ("1 detections") | Open, cosmetic |
| The agents write queries with `process.args`, which the lab telemetry does not have; the SIEM refuses them and they are re-run | Synthetic lab telemetry (a stated limit). The refusals are recorded and each hypothesis was still tested |
| Hunt counted 28 where the rule has 29 alerts | Not a fault: the hunt query was narrower than the rule |
| The copy of `CLAUDE.md` preloaded in the sub-agent's session was older than the file | The test harness: a sub-agent inherits the parent session's copy. The brief tells it to read the file |
