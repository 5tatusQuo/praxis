# Operator test 5: a whole client life, documented commands only

Date: 2026-11-18 to 19 · Client: `pellwick` (fictional building contractor and engineering firm, 50 endpoints, new sector `buildeng`)

A fifth fresh sub-agent ran the same strict task as test 4, after the fixes
from that test (PR #62).

**Result: all eleven steps completed by the agent itself.** Its report ends:

```
WORKAROUNDS: 0
UNDOCUMENTED COMMANDS: 1
STEPS NOT COMPLETED OR NOT RUN BY ME: 0
```

No `git`, `gh`, `ssh` or `curl`, no reads of repo files other than the two
guides, no hand edits, no permission refusals.

The one undocumented command was `./px change status 67`: the guides named
`change status` only for listing open pull requests, and the agent found the
per-number form through `./px change --help`, which the guides do document.
It is read-only and shows what `change show` shows. The runbook now names it.

| Step | Outcome | Pull request |
| --- | --- | --- |
| Create the client | Sector `buildeng` with six ATT&CK groups; client with the `baseline` pack | |
| Connect to the SIEM | Read `ok` ("write correctly refused"), deploy `ok` | |
| Lab telemetry | 11,100 events; logons from 30 of 50 hosts; file events silent for 4 days | |
| Deploy the baseline | PRX-000001 to 000003 `created`, `succeeded`; drift check clean | #63 |
| Coverage | 7 covered, 522 detection gaps, 177 visibility gaps; threat-weighted 3.91%. File components 0 ("11 techniques are not visible because of it"); logon components 3 ("58 techniques rely on it at reduced confidence") | |
| Hand-written detection | PRX-000017, network scanning tool started on a Windows host (T1046); lab 4 of 4; shadow, then promoted; threat-weighted 5.5% | #64, #65 |
| Agent rule pack | First proposal: Reviewer verdict fail. The command said what to do; the agent closed it and planned again. Second proposal: verdict pass, scores 94 and 88, read with `change show --diff`, merged, running in shadow | #66 (closed), #67 |
| Noisy rule, then tuning | 29 alerts; exclusion "removes 25 of 29 matches; 4 remain"; `./px tuning` showed 29 without, 4 with, 25 suppressed | #68 |
| Hunt | Five hypotheses, one durable | #69 |
| Offboard | 6 rules, 2 keys, space and telemetry removed; "verified in the SIEM: no PRAXIS rules, no active keys, no Kibana space, no telemetry"; kept items listed | #70 |

The sub-agent merged #63 to #65 and #67 to #70 and closed #66, all under
approvals written into its task. The main session ran nothing for it.

## Independent check

After the test the main session queried the SIEM directly, read-only: data
only in the `acme` and `globex` namespaces (plus the lab's own scratch
namespace); PRAXIS keys only for the lab, `acme` and `globex`; Kibana spaces
`default`, `acme` and `globex`.

## Friction it logged, none of which blocked a step

| Finding | Outcome |
| --- | --- |
| `change status <number>` not in the guides | Documented |
| Two Reviewer runs disagreed about the same query construct in PRX-000019 (a blocker the first time, passed the second) | Open. PRX-000019 is staged and runs nowhere; review it before anyone promotes it |
| Sector text search is noisy; the agent took most groups from existing profiles | Known limit, stated in the runbook: ATT&CK does not index groups by target sector |
| Four near-identical sector profiles now exist (`construction`, `engineering`, `architecture`, `building`, `buildeng`) | Made by these tests on purpose; nothing flags overlap between profiles |
| `client show` prints an empty `detections` list above `detections_running` | Open, cosmetic |
| Coverage timestamps are UTC; record ids use the workstation's date | Open, cosmetic |
| The hunt's wording did not separate four test positives from benign hits | Open; counts are from code, wording is the model's |
| Each merge takes five to ten minutes | By design, documented |
