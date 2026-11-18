# Operator test 10: after the last fixes; same harness refusal

Date: 2026-11-19 · Client: `farrowby-lund` (fictional building and engineering firm, 50 endpoints, new sector `sitebuild`)

A tenth fresh sub-agent ran the strict task on `main` after PR #110. Its
report ends:

```
WORKAROUNDS: 0
UNDOCUMENTED COMMANDS: 0
STEPS NOT COMPLETED OR NOT RUN BY ME: 1
```

**As in tests 8 and 9, the one command it did not run was the merge of the
rule pack (PR #114).** Its session's permission system refused it
("Destructive or Unwanted Actions"). It stopped and reported; the main session
read the pull request, merged it, and resumed the same sub-agent, which then
merged the tuning and hunt pull requests and offboarded the client itself.
Three runs in a row have hit this. It is the Claude Code permission system
guarding a sub-agent's first merge of an agent-opened pull request, not
PRAXIS. Only a permission rule in the owner's settings would change it, so no
further run was started. Test 7 remains the unassisted pass.

| Step | Outcome | Pull request |
| --- | --- | --- |
| Create the client | Six groups from eight lookups; sector `sitebuild`; client with the `baseline` pack | |
| Connect to the SIEM | Read `ok` ("write correctly refused"), deploy `ok` | |
| Lab telemetry | 11,100 events; logons from 32 of 50 hosts; file events silent for 4 days | |
| Deploy the baseline | PRX-000001 to 000003 `created`, `succeeded`; drift check clean | #111 |
| Coverage | 7 covered, 522 detection gaps, 177 visibility gaps; threat-weighted 2.97% | |
| Hand-written detection | PRX-000029, certutil download from a URL (T1105); `detection write` listed PRX-000023 as already on the technique; lab 4 of 4; shadow, then promoted; threat-weighted 5.03% | #112, #113 |
| Agent rule pack | Two picks (PRX-000030, PRX-000031), Reviewer verdict pass on the first proposal; read in full by the sub-agent; **merged by the main session**; running in shadow | #114 |
| Noisy rule, then tuning | 34 alerts, 30 from a backup agent; exclusion "removes 30 of 34 matches; 4 remain"; `./px tuning` showed 34 without, 4 with, 30 suppressed | #115 |
| Hunt | Four hypotheses, two durable; one refused query recorded under `failed_queries` | #116 |
| Offboard | 6 rules, 2 keys, space and telemetry removed; "verified in the SIEM: no PRAXIS rules, no active keys, no Kibana space, no telemetry"; then `sector remove`, `pack remove`, `hunt-remove` | #117 |

The sub-agent merged #111 to #113 and #115 to #117. The main session merged #114.

This run used PR #110's two changes: `detection write` printed
`already_on_these_techniques`, and `change show` was read while checks were
unfinished without confusion being reported.

## Independent check

After the run the main session queried the SIEM directly (read-only): data,
active PRAXIS keys and Kibana spaces exist for `acme` and `globex` only. No
pull request is open.

## Friction reported, and what was done

| Friction | Action |
| --- | --- |
| Help shows options the guides did not name (`--pr/--no-pr`, `--kind`, `--from-client`, `--events-per-day`, `--remove`, `--replace`, `--no-delete-space`, `--no-delete-data`) | The runbook now names them in one table |
| A command about an unknown client exited with code 2; the runbook said 1 | The runbook now says a failed command exits with a code that is not 0 |
| `attack groups construction` listed one group twice | Not reproduced: the main session ran the same command and got one entry |
| `client add` does not mention `lab source` in its next steps | Not changed: shaping the lab is optional, and the runbook's step 3 covers it |
| The Tuner wrote one exclusion that a second one already covers | Open. Harmless: code measured the impact and checked that every positive test still fires. A check for redundant entries would tidy it |
| A hunt assessment's wording did not match its measured hits | Not fixable in code: the text is the agent's, the numbers are measured. The pull request shows both |
| A pull request description's table row wrapped | Display only: `change show` wraps long lines at the terminal width |
| Hunt ids are cut mid-word | Not changed: ids are capped at a fixed length so branch names stay valid |
| Going live takes two pull requests (shadow, then promote) | By design: every new rule runs in shadow first |
| Unassigned detections stay after offboarding | By design: the library is shared |

The two runbook changes were made after the run. They change no command.
