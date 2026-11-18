# Operator test 4: stricter rules, a building and engineering client

Date: 2026-11-18 · Client: `harlowmere` (fictional, 55 endpoints, new sector `building`)

Test 3 was first recorded as a pass. It was not one: its agent ran read-only
`git diff` and `git show` to read pull requests, which are not documented
PRAXIS commands, and the fix (`change show --diff`) had not been used by a
fresh agent. Test 4 ran after that fix (PR #54) with a stricter task: use only
commands that CLAUDE.md and the runbook document, and list every other
command, read-only ones included.

**Result: not a pass.** No workarounds, no `git`, every step run by the agent,
but:

- **Step 7 was not completed.** The Reviewer agent failed the proposed pack
  (PR #58): one rule's ATT&CK mapping overstated what it detects. The
  sub-agent read the proposal with `change show --diff`, agreed, and did not
  merge it. That is the gate working, but the pack never ran in shadow, and
  the runbook did not say what to do with a failed verdict.
- **11 undocumented commands**, all read-only: `./px detection list`, and
  `--help` on ten single commands. The guides documented help for groups only.

| Step | Outcome | Pull request |
| --- | --- | --- |
| Create, connect, telemetry, baseline | Done; 10,900 events; three rules `created`, `succeeded` | #55 |
| Coverage | 7 covered; file components silent ("11 techniques are not visible because of it"); logons 35/55 hosts ("58 techniques rely on it at reduced confidence") | |
| Hand-written detection | PRX-000016, remote command execution over WinRM (T1021.006); lab 4 of 4; shadow, then promoted | #56, #57 |
| Agent rule pack | Proposed, Reviewer verdict fail, not merged | #58 (closed) |
| Tuning | 34 alerts; exclusion "removes 30 of 34"; `./px tuning` showed 30 suppressed | #59 |
| Hunt | Four hypotheses, two durable | #60 |
| Offboard | Verified in the SIEM: no rules, keys, space or telemetry | #61 |

The sub-agent merged #55 to #57 and #59 to #61. The main session closed #58
after the test.

## Findings, and what was done (PR #62)

| Finding | Fix |
| --- | --- |
| `pack plan` exits normally on a failed verdict and nothing says what to do | It prints "do not merge" and the commands to close the proposal and plan again; the runbook has the same |
| Per-command `--help` and `detection list` were not in the guides | Documented in CLAUDE.md and the runbook, with `alerts --timeout` |
| Offboarding did not mention the client's open pull request | It names each one with the command to close it |
| Top gaps showed nothing "in the library" for a parent technique whose sub-techniques had rules | A rule on a sub-technique is listed for its parent |
| The Tuner's exclusion pins the exact command line, so the same agent on another drive would alert again | Open. This is the Tuner choosing the narrowest safe exclusion; widening it is a person's call |
| The hunt's summary did not separate the four test positives from the benign hits | Open. The counts come from code; the wording is the model's |
