# Operator test 3: a fresh AI session runs a whole client life alone

Date: 2026-11-18 · Client: `brindlewick` (fictional, 70 endpoints, new sector `architecture`)

A third sub-agent with no knowledge of PRAXIS beyond the repository ran the
task after the fixes from test 2 (PR #46). The approvals a user would give
(merge the agents' pull requests for this client after reading them; offboard
this client with full deletion) were written into the task, so the agent did
not need to stop.

**Result: all eleven steps completed by the agent itself, but not a pass.**
Its report ends `WORKAROUNDS: 0` and `STEPS NOT RUN BY ME: 0`. It also ran
read-only `git diff` and `git show` three times to read pull requests, which
are not documented PRAXIS commands. The sector was `architecture`, not
building and engineering. Tests 4 and 5 followed.

## What happened

| Step | Outcome | Pull request |
| --- | --- | --- |
| Create the client | Sector `architecture` with five ATT&CK groups; client with the `baseline` pack | |
| Connect to the SIEM | Read `ok` ("write correctly refused"), deploy `ok` | |
| Lab telemetry | 11,300 events; logons from 40 of 70 hosts; network events silent for 3 days | |
| Deploy the baseline | PRX-000001 to 000003 `created`, `succeeded`; drift check clean | #47 |
| Coverage | 7 covered, 522 detection gaps, 177 visibility gaps; threat-weighted 2.4%. Network component 0: "silent: no events in 24h; 15 techniques are not visible because of it". Logon components 3 (40/70 hosts) | |
| Hand-written detection | PRX-000013, Windows system process name running from an unusual path (T1036.005); lab 4 of 4; shadow, then promoted. Threat-weighted coverage 6.59% | #48, #49 |
| Agent rule pack | Two rules (PRX-000014 on T1021.001 and T1112, PRX-000015 on T1560.001), scores 94 and 94, Reviewer verdict pass. The agent read the pull request, then merged it. Left in shadow | #50 |
| Noisy rule, then tuning | 25 benign backup-agent events and 4 true positives replayed; 29 alerts. The Tuner proposed one three-condition exclusion. After the merge, `./px tuning` showed 29 matches without tuning, 4 with, 25 suppressed | #51 |
| Hunt | Five hypotheses, 0 hits, two marked durable; the summary says the silent network source prevented two tests | #52 |
| Offboard | 6 rules, 2 keys, the Kibana space and the telemetry removed. PRAXIS printed "verified in the SIEM: no PRAXIS rules, no active keys, no Kibana space, no telemetry", then listed what it kept in the library | #53 |

The sub-agent merged all seven pull requests (#47 to #53), under the approvals
in its task. The other clients were not touched.

## Independent check

After the test the main session queried the SIEM directly, read-only:
the only client namespaces with data are `acme` and `globex`; the only
PRAXIS keys are the lab key and the read and deploy keys of `acme` and
`globex`; the only Kibana spaces are `default`, `acme` and `globex`. Nothing
of the three test clients is left.

## Findings, and what was done about each

None needed a workaround. The agent ran read-only `git diff` three times to
read what a pull request changed, because `change show` listed file names
only; that was the one place it left `./px`.

| Finding | Outcome |
| --- | --- |
| `change show` did not show a pull request's contents | Fixed: `./px change show <number> --diff` |
| Top gaps did not say the library already had a detection for a gap | Fixed: an "in the library" column, and the runbook says to assign before writing |
| Coverage gave the cost of a silent source but not of a partial one | Fixed: a partial source says how many techniques rely on it |
| The alert wait timed out with advice to check the rule, when the rule had only not run yet | Fixed: the message says a rule runs every few minutes and to wait longer |
| The hunt pull request's title was cut mid-word | Fixed: cut at a word, with an ellipsis |
| Visibility-gap total not explained; alert counts do not drop after tuning; replayed events add host names | Documented in the runbook under "Reading coverage" |
| No way to re-check an offboarded client later | Not fixed, stated in the runbook: once a client leaves the content, PRAXIS no longer knows its space or keys. Offboarding verifies at the time and prints the result |
| No command removes a sector profile or a rule-pack record | Not fixed, stated in the runbook: they are shared history |
| The pack pull request's "Before you merge" notes described a change the shipped queries already had | Open. The notes are the model's wording; the numbers and the lab result come from code. Listed under open problems |
| The agents wrote a new T1560.001 rule although the library held an unassigned one | Open. The Curator picks from the external catalog; it does not yet propose assigning an existing library detection |
| A merge takes five to eight minutes; seven merges were most of the elapsed time | By design, documented: every change is tested in the lab and each rule's first run is awaited |
| A rule goes live in two merges (shadow, then promote) | By design |

## Left in the library by the three tests

Detections no client runs now: PRX-000008 to 000010 (test 1's pack, staged),
PRX-000011 (test 2, production), PRX-000012 (test 2's pack, staged),
PRX-000013 (test 3, production), PRX-000014 and 000015 (test 3's pack,
staged). Sector profiles `construction`, `engineering` and `architecture`.
Three rule-pack records and three hunt records. All are valid content;
whether to keep, assign or deprecate the detections is the owner's decision.
