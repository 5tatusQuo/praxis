# Operator test 9: the current product, start to finish in under an hour

Date: 2026-11-19 · Client: `dunmerrow` (fictional building and engineering firm, 45 endpoints, new sector `groundworks`)

A ninth fresh sub-agent ran the strict task after PR #102, which fixed
everything test 8 reported. Its task also asked it to remove its own sector
profile, pack record and hunt record when offboarding. Its report ends:

```
WORKAROUNDS: 0
UNDOCUMENTED COMMANDS: 0
STEPS NOT COMPLETED OR NOT RUN BY ME: 1
```

**The one command it did not run was the merge of the rule pack (PR #106).**
As in test 8, the sub-agent's own session refused its first merge of an
agent-opened pull request ("Destructive or Unwanted Actions"). It stopped and
reported. The main session read the pull request and merged it, on the owner's
earlier word to keep going, and resumed the same sub-agent. The same session
then ran the tuning merge, the hunt merge and the offboarding without a
refusal. This is the test harness guarding a sub-agent, not PRAXIS. Test 7
remains the run a fresh agent completed with no help at all.

| Step | Outcome | Pull request |
| --- | --- | --- |
| Create the client | Five groups chosen from nine lookups; sector `groundworks`; client with the `baseline` pack | |
| Connect to the SIEM | Read `ok` ("write correctly refused"), deploy `ok` | |
| Lab telemetry | 11,100 events; logons from 30 of 45 hosts; file events silent for 4 days | |
| Deploy the baseline | PRX-000001 to 000003 `created`, `succeeded`; drift check clean | #103 |
| Coverage | 7 covered, 522 detection gaps, 177 visibility gaps; threat-weighted 3.26% | |
| Hand-written detection | PRX-000026, PsExec client or service binary started (T1021.002, T1569.002); lab 5 of 5; shadow, then promoted; covered 11, threat-weighted 8.61% | #104, #105 |
| Agent rule pack | Two picks (PRX-000027, PRX-000028), Reviewer verdict pass on the first proposal; read in full by the sub-agent; **merged by the main session**; running in shadow | #106 |
| Noisy rule, then tuning | 29 alerts, 25 from a backup agent; exclusion "removes 25 of 29 matches; 4 remain"; `./px tuning` showed 29 without, 4 with, 25 suppressed | #107 |
| Hunt | Three hypotheses, two durable; two refused queries recorded under `failed_queries`; the planner rewrote them and the rewrites ran | #108 |
| Offboard | 6 rules, 2 keys, space and telemetry removed; "verified in the SIEM: no PRAXIS rules, no active keys, no Kibana space, no telemetry"; then `sector remove`, `pack remove` and `hunt-remove` | #109 |

The sub-agent merged #103 to #105 and #107 to #109. The main session merged #106.

## What this run showed about PR #102

- **Merge time.** The lab check took about one minute per pull request (it was
  about eight). The whole client life, seven merges, took under an hour of
  wall time; earlier runs took about ninety minutes.
- `hunt-remove` removed a real record. `attack groups` gave no false matches
  on "play"; an empty search no longer looked like a failure.
- No hunt query hit the counting limit, so the "too broad" mark was not
  triggered. It has a unit-level path only.

## Independent check

After the run the main session queried the SIEM directly (read-only): data,
active PRAXIS keys and Kibana spaces exist for `acme` and `globex` only. No
pull request is open. Sectors are `finance` and `healthcare`; the only pack
record is `acme-2026.12.0`.

## Friction reported, and what was done

| Friction | Action |
| --- | --- |
| `change show` lists three checks while they run; the lab check appears only after the others pass | `change show` now adds a note saying so, and that `change merge` waits for every check |
| `detection write` gave no warning that the library already has rules on the technique | It now lists them under `already_on_these_techniques` |
| A pack record's "why" text described a rule wrongly; the Reviewer noted it and passed | Not changed. Agent text can lag the facts; the query, tests and scores come from code. `./px pack restyle` rewrites the text |
| `attack groups building` matches the verb | Not changed: a text search cannot tell. The runbook says to read each match's context |
| Hunt counted 28 where the rule has 29 alerts | Not a fault: the hunt query was narrower than the rule |
| Alerts took three minutes to arrive | By design: rules run every five minutes |
| Detections written for the client stay in the library | By design: the library is shared. `detection deprecate` retires one |

The two "now" changes were made after the run and checked by the main session.
