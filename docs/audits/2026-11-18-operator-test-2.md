# Operator test 2: a second fresh AI session, a new client, onboarding to offboarding

Date: 2026-11-18 · Client: `vantmoor` (fictional, 45 endpoints, new sector `engineering`)

A new sub-agent with no knowledge of PRAXIS beyond the repository ran the same
task as operator test 1, after the fixes from that test (PR #36), with one
more step: offboard the client at the end.

**Result: all eleven steps completed. The agent reported `WORKAROUNDS: 0`.**
It did not run every step itself: its own session refused to act on approvals
relayed by another agent, so the main session ran five commands for it. All
five were ordinary PRAXIS commands.

## What happened

| Step | Outcome | Pull request |
| --- | --- | --- |
| Create the client | Sector `engineering` with five ATT&CK groups; client with the `baseline` pack | |
| Connect to the SIEM | Read `ok` ("write correctly refused"), deploy `ok`; two keys written | |
| Lab telemetry | 13,900 events; logons from 30 of 45 hosts; file events silent for 4 days | |
| Deploy the baseline | PRX-000001 to 000003 `created`, `succeeded`; drift check clean | #39 |
| Coverage | 7 covered, 537 detection gaps, 162 visibility gaps; threat-weighted 3.99%. File components scored 0 (silent); logon components 3 (30/45 hosts) | |
| Hand-written detection | PRX-000011, password-protected archive with rar or 7-Zip (T1560.001); lab 4 of 4; shadow, then promoted. Threat-weighted coverage 7.58% | #40, #41 |
| Agent rule pack | One rule (PRX-000012, T1018), Reviewer verdict pass; the agents left the second slot empty rather than pick a rule that cannot run. Left in shadow | #42 |
| Noisy rule, then tuning | 25 benign backup-agent events and 4 true positives replayed; 29 alerts. The Tuner proposed one three-condition exclusion: "removes 25 of 29 matches; 4 remain". After the merge, 5 more benign events raised no alert and 4 more true positives did | #43 |
| Hunt | Four hypotheses, 0 hits each, one marked durable | #44 |
| Offboard | 5 rules, 2 keys, the Kibana space and the telemetry removed; 4 content files removed | #45 |

## Who merged what

- The sub-agent merged #39, #40, #41 (its own changes) and #42 (the agents' pack).
- The main session, acting as the user under the goal's written permission, merged #43 (tuning) and #44 (hunt), ran the offboarding, and merged #45.

Why: the sub-agent asked before merging the agent-opened pull requests, as
CLAUDE.md requires. The main session answered as the user. The sub-agent
merged #42 on that answer; then its session's permission system refused
`./px change merge 43`, and it decided, correctly under its own rules, that
an approval relayed by another agent is not the user's consent. It refused to
continue with merges or deletion. This is a property of the test harness, not
of PRAXIS: a real session takes its approvals from the person directly.
Operator test 3 gives the approvals in the task itself.

## Findings, and what was done about each (PR #46)

| Finding | Fix |
| --- | --- |
| `status` still listed the first test's offboarded client in the server's coverage and proposals | Offboarded clients no longer show in `status`, the fleet page or the rule-pack page; history stays in the database |
| Offboarding did not say what it leaves in the library (pack record, hunt record, a staged detection no client runs) | It lists what it kept and why, and names the commands for a detection no client runs |
| No way to confirm from PRAXIS that the SIEM side is gone | Offboarding queries the SIEM afterwards and prints what it verified; it fails if anything is left |
| No "what does this tuning suppress" view; the agent proved it by replaying events | `./px tuning <rule> --client <id>` |
| The hunt printed a sequence query without its body | Output no longer treats square brackets as formatting |
| `attack groups engineering` matched "social engineering" | Each match shows the words around it; the runbook says a sector search is a text search and ATT&CK does not index groups by target sector |
| Coverage did not say what a silent source costs | A silent source's row says how many techniques are not visible because of it |
| `status` called a merged pack "proposed" in one place and "merged, in shadow" in another | One wording |
| Runbook said a merge takes "a few minutes"; it took 7 to 9 | Runbook says five to ten minutes, and why |
| `--budget 2` gave one rule | Documented: the budget is a ceiling |
| Alerts show pseudonyms for users and hosts; the runbook did not say so | Documented |
| Agent pull requests carried a tool attribution that did not match the model | Removed; they say PRAXIS opened them for its agents |
| Two pull requests that both change `packs.lock` might clash | They did not clash here. `change merge` now updates a pull request's branch when `main` has moved, so its checks run against current `main` |

Not PRAXIS: the sub-agent's session was given a second, shorter copy of
CLAUDE.md by the harness; it followed the file on disk.

## Still slow

A merge takes 7 to 9 minutes: the checks replay every detection's test events
in the lab, then the deploy waits for each rule's first run. One rule from
written to live is two merges. This is by design (nothing reaches a client
untested) but it is the largest wait in an operator's day.
