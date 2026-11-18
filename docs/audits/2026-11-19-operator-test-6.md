# Operator test 6: documented commands only, but the pack step failed

Date: 2026-11-19 · Client: `corvenhallow` (fictional building and engineering firm)

A sixth fresh sub-agent ran the strict task after the fixes from test 5
(PRs #71 and #72). **Not a pass.** Its report ends:

```
WORKAROUNDS: 0
UNDOCUMENTED COMMANDS: 0
STEPS NOT COMPLETED OR NOT RUN BY ME: 1
```

The step it could not complete was the agent rule pack. The Reviewer failed
three proposals in a row. Each time the Curator picked the same candidate
(a winget rule) to close T1059, and the detection the Engineer wrote did not
map to T1059, so the pack would have overstated coverage. The Reviewer was
right to fail it; the fault was that planning again produced the same pick.

Every other step completed: create, connect, lab telemetry, baseline, coverage,
hand-written detection, tuning, hunt, offboarding.

Pull requests: #73 to #75, #79, #81 and #82 merged by the sub-agent under
approvals written into its task. #76, #77, #78 (the failed packs) and #80
closed by the sub-agent.

## Findings, and what was done about each (PR #83)

| Finding | Fix |
| --- | --- |
| Planning again after a failed review picked the same candidate three times | The pack remembers the candidates that failed review; the Curator is told not to pick them, and code drops them if it does |
| A rule was picked to close a technique it does not map to | Code rejects the pick when the written detection's techniques do not include the picked technique or one of its sub-techniques |
| The Reviewer did not re-check what it had failed before | The Reviewer gets the earlier blockers and must check each one |
| A hunt with the same topic on the same day would overwrite another client's record | The hunt id gets `-2`, `-3` and so on when the record exists |
| `change merge` ended with exit code 1 and no next step when the deploy was still queued | It says the change is merged and to run the same command again; a second run waits for the deploy of an already merged pull request |
| `change show` printed `checks: {}` straight after a pull request opened | It says none are reported yet and that `change merge` waits for them |

These fixes had unit tests only when they merged. Test 7 was their first live use.
