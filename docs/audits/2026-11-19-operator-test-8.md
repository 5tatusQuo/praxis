# Operator test 8: the fixes made after test 7, used by a fresh agent

Date: 2026-11-19 · Client: `thackwell` (fictional building and engineering firm, 55 endpoints, new sector `sitecraft`)

An eighth fresh sub-agent ran the strict task after PRs #91, #92 and #93. Its
task also asked it to look up the sector's threat groups itself, and to remove
its own sector profile and pack record when offboarding. Its report ends:

```
WORKAROUNDS: 0
UNDOCUMENTED COMMANDS: 0
STEPS NOT COMPLETED OR NOT RUN BY ME: 1
```

**The one step it did not run was the merge of the rule pack (PR #97).** Its
own session's permission system refused `./px change merge 97` ("Destructive
or Unwanted Actions"). It stopped and reported, as told. The owner then told
the main session to keep going; the main session read the pull request, merged
it, and resumed the same sub-agent. This is the test harness, not PRAXIS: the
same sub-agent's later merges of agent-opened pull requests (#98, #99) were
not refused, and neither were those in tests 3 to 7.

So test 7 remains the run that a fresh agent completed entirely alone. Test 8
shows that the changes made after it work in a fresh agent's hands.

| Step | Outcome | Pull request |
| --- | --- | --- |
| Create the client | Seven groups found with `attack groups` (fourteen search words); sector `sitecraft`; client with the `baseline` pack | |
| Connect to the SIEM | Read `ok` ("write correctly refused"), deploy `ok` | |
| Lab telemetry | 11,100 events; logons from 35 of 55 hosts; file events silent for 4 days | |
| Deploy the baseline | PRX-000001 to 000003 `created`, `succeeded`; drift check clean | #94 |
| Coverage | 7 covered, 522 detection gaps, 177 visibility gaps; threat-weighted 4.06% | |
| Hand-written detection | PRX-000023, bitsadmin download from a URL (T1105); lab 4 of 4; shadow, then promoted; threat-weighted 5.74% | #95, #96 |
| Agent rule pack | Two picks (PRX-000024, PRX-000025), Reviewer verdict pass on the first proposal; read in full by the sub-agent; **merged by the main session**; running in shadow | #97 |
| Noisy rule, then tuning | 34 alerts, 30 from a backup agent; exclusion "removes 30 of 34 matches; 4 remain"; `./px tuning` showed 34 without, 4 with, 30 suppressed | #98 |
| Hunt | Four hypotheses, two durable; two queries the SIEM refused are in the record under `failed_queries` and in the pull request | #99 |
| Offboard | 6 rules, 2 keys, space and telemetry removed; "verified in the SIEM: no PRAXIS rules, no active keys, no Kibana space, no telemetry"; then `sector remove sitecraft` and `pack remove thackwell-2026.12.0` | #100 |

The sub-agent merged #94 to #96 and #98 to #100. The main session merged #97.

## What this run exercised from the changes after test 7

| Change | Used live |
| --- | --- |
| Hunt records keep failed queries as data (PR #92) | Yes: two failed queries recorded with the SIEM's error |
| `sector remove`, `pack remove` (PR #92) | Yes: both removed a real item, shipped in #100 |
| `attack groups engineering` skips "social engineering" (PR #92) | Yes: the groups were chosen from lookups, not copied |
| `detection write` prints the next step; `status` shows offboarded packs as records (PR #91) | Yes; no friction reported |
| Failed-candidate memory and pick-mapping guard for packs (PR #83) | **No.** The pack passed on the first proposal again. Unit tests only |

## Independent check

After the run the main session queried the SIEM directly (read-only): data,
active PRAXIS keys and Kibana spaces exist for `acme` and `globex` only, plus
the shared lab. No pull request is open.

## The MCP server, used by a fresh session

A sub-agent's session does not load a project's MCP servers. So a separate
fresh headless Claude Code session was started in the repo with only the
`praxis` MCP tools allowed and no shell. It called `status`, `get_coverage`
and `search_catalog` with no errors and saw all 18 tools. It found that
`CLAUDE.md` overstated the tools ("the same actions"); PR #93 corrected that:
the tools read and author, and shipping, the agents, provisioning and
offboarding are `./px` only.

## Friction reported, not fixed (backlog)

- The top-gaps table can list a library detection twice in one row.
- `attack groups` exits 1 when nothing matches, and `play` matches inside
  other words ("Playbook").
- T1078 shows visibility 4 while both logon components score 3.
- A hunt hypothesis whose own query failed can be marked `tested: true` from a
  broader fallback query (here 1000 logons for an RDP hypothesis). The text
  says so; the table does not.
- `change show` lists checks as pending for some minutes after a pull request
  opens, so "checks passing" can only be seen through `change merge`.
- `sector remove` and `pack remove` each print a next step that reads as a
  separate pull request; one submit covers them all.
- MCP wording: `blind_rule` counts techniques while `rules.blind` counts
  rules; `search_catalog` says "this client's SIEM" but takes no client.
- Merges take seven to fifteen minutes, also for changes that deploy nothing.
