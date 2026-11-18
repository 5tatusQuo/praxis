# Runbook: operate a client, start to finish

This is the whole life of one client, in order. Every step is one command. A
person can follow it; so can an AI assistant working for them.

The example client is `ironbridge`, a fictional construction firm with 40
Windows endpoints. Replace the name and sector with your own.

## How to run commands

Use `./px` from the repo root for everything:

```bash
./px status          # where everything stands; run this first, and whenever unsure
./px --help          # every command
./px client --help   # every command in a group
./px client add --help   # one command's options
./px detection list   # the detections in the library and who runs them
```

`./px` runs `praxis` connected to the server named in `.env`, so SIEM reads,
lab tests, agents and server steps all work the same way. Add `--json` to get
data instead of a table. A failed command exits with code 1 and one line
saying what is wrong and what to do.

## Rules

- **Client names are invented.** Never put a real company, hostname or
  credential in this repo: it is public.
- **Every change ships through a pull request, and merging deploys it.**
  `./px change submit` opens one; `./px change merge` waits for the checks,
  merges, waits for the deploy and reports what happened to each rule.
- **Agents propose, a person approves.** `pack plan`, `tune` and `hunt` each
  start from `main`, open a pull request on a branch that starts with `ai/`,
  and return you to `main`. Read it with `./px change show` before merging.
- **Several `./px` commands can run at once**, for example while a merge waits.
- **Offboarding deletes things for good.** It asks for `--yes`.

## 1. Create the client

A client's sector needs a threat profile: the ATT&CK groups that target it.
Gaps are ranked by how many of those groups use each technique.

```bash
./px sector list                          # sectors that already have one
./px attack groups construction           # searches names and descriptions; read each match's context
./px attack groups akira                  # or find a group by name or alias
./px sector add construction \
  --description "Ransomware crews that have hit construction and engineering firms." \
  --group G1024 --group G1032 --group G0096 --technique T1490=0.3

./px client add ironbridge --name "Ironbridge Construction" \
  --sector construction --endpoints 40
```

Name the sector after the client's industry, in one lower-case word. ATT&CK
lists threat actors as groups; ransomware families and tools are not groups.
ATT&CK does not index groups by the sector they target, so a sector search is
a text search of group descriptions: check each match's context, and add
groups you know from your own intelligence.

`client add` writes the manifest, a lab telemetry profile that covers every
log source the client's rules read, and its `packs.lock`. The client gets the
`baseline` content pack unless you pass `--pack`. Check it:

```bash
./px client show ironbridge
```

## 2. Connect it to the SIEM

```bash
./px client provision ironbridge
```

This creates the client's Kibana space and its own read and deploy keys (the
lab key is shared by every client, so a second client gets two new keys, not
three). It then hands the keys to the runner and the API on the server, which
rewrites the key files for every client and restarts the API, and ends with a
connection check. Expect `ok` for `read`, with "write correctly refused", and
`ok` for `deploy`. It is safe to repeat. `./px client check ironbridge`
repeats only the check; `--rotate` replaces the keys.

## 3. Give it telemetry

```bash
./px lab seed ironbridge
```

Writes 14 days of synthetic events to each source in the client's lab
profile. The nightly workflow tops it up from then on.

The profile starts with the sources the client's rules read. To model what a
client really sends, shape it before seeding, for example logons from only
some hosts, or a source that went quiet:

```bash
./px sources                                                     # what the lab can generate
./px lab source ironbridge logs-system.security --hosts 25
./px lab source ironbridge logs-endpoint.events.file --silent-for-days 5
```

## 4. Deploy

```bash
./px change submit "Onboard ironbridge"
./px change merge <number>
```

`change merge` takes five to ten minutes: the checks replay every detection's
test events in the lab, and the deploy waits for each rule's first run. It prints progress while it waits for the
checks, merges, and waits for the deploy; only the clients a change affects
are redeployed. It reports each rule as `created` and its first run as
`succeeded`. A rule the client sends no telemetry for reports `no telemetry`:
it is deployed, and coverage will show it as a blind rule.

## 5. Read the coverage

```bash
./px coverage ironbridge          # --summary for the headline numbers, --json for everything
./px drift ironbridge             # does the SIEM match Git?
```

You get a visibility score per data component, each rule's status, and the top
detection gaps ranked by threat weight. A rule on a sub-technique also covers
its parent technique, so "covered" can be higher than the number of techniques
listed against the rules. `docs/visibility-scoring.md` explains
every number. The same view is on the dashboard: `deploy/dashboard.sh` opens it.

## 6. Add a rule by hand

Write one spec file with the metadata, the query, the README text and the
test events. Keep it anywhere, inside or outside the repo: `change submit`
only includes files under `content/`. `./px detection write --schema` prints
the format and each text field's limits; this is a complete example:

```yaml
# certutil.yml
slug: certutil-remote-download
name: Certutil used to download a file
intent: >-
  Detects certutil fetching a file from a URL, a built-in way to bring tools
  onto a host without a browser or PowerShell.
severity: medium                  # low, medium, high, critical
risk_score: 47
attack:
  - technique: T1105
    tactic: TA0011                # ./px attack technique T1105 lists the valid tactics
data_components: [Process Creation]
pyramid_tier: ttp                 # hash, ip, domain, artifact, tool, ttp
indices: [logs-endpoint.events.process-*]     # ./px sources lists what exists
query: |
  process where host.os.type == "windows" and event.type == "start" and
    (process.name : "certutil.exe" or ?process.pe.original_file_name : "CertUtil.exe") and
    process.command_line : ("*urlcache*", "*verifyctl*") and
    process.command_line : ("*http://*", "*https://*", "*ftp://*")
false_positives:
  - Administrators who fetch certificates or revocation lists by hand.
summary: >-
  Fires when certutil.exe starts with a download option and a URL. Attackers
  use this built-in tool to bring files onto a host.
how_it_works: >-
  The query looks at Windows process starts. It matches certutil.exe by name or
  by original PE file name, so a renamed copy still matches. The command line
  must contain urlcache or verifyctl, and a URL.
blind_spots: |
  - Other download tools (bitsadmin, curl, PowerShell) need their own rules.
  - Hosts that do not log command lines are invisible to this rule.
soc_triage: |
  1. Read the URL in the command line and check its reputation.
  2. Find the file that was written and check its hash.
  3. Check the parent process and the user.
positive_tests:                   # events that must fire
  - name: urlcache-download
    events:
      - event: {category: [process], type: [start], kind: event}
        host: {name: ws-lab-07, os: {type: windows}}
        process:
          name: certutil.exe
          command_line: 'certutil.exe -urlcache -split -f http://example.invalid/tool.exe C:\Users\Public\tool.exe'
          pe: {original_file_name: CertUtil.exe}
negative_tests:                   # benign look-alikes that must stay quiet
  - name: certutil-hash-file
    events:
      - event: {category: [process], type: [start], kind: event}
        host: {name: ws-lab-07, os: {type: windows}}
        process:
          name: certutil.exe
          command_line: 'certutil.exe -hashfile C:\Temp\setup.msi SHA256'
          pe: {original_file_name: CertUtil.exe}
```

```bash
./px detection write certutil.yml                     # prints the id it assigned
./px lab test PRX-000007                              # every case must pass
./px detection assign PRX-000007 --client ironbridge  # or --content-pack baseline, for everyone
./px change submit "Add certutil download detection"
./px change merge <number>
```

`./px detection show <id>` prints an existing detection, including a test
event, if you want one to model yours on.

A new detection is `staged`: it deploys in shadow mode (named `[shadow] ...`,
lowest severity, tagged `praxis-shadow`) and gives no coverage yet. To take it
live:

```bash
./px detection promote PRX-000007
./px change submit "Promote PRX-000007" && ./px change merge <number>
```

Each text field has a word limit and a sentence-length limit, listed by
`--schema` (most sentences 25 words, triage steps 20). The command says which
field to shorten. The query must not name indices.

## 7. Have the agents propose a pack

```bash
./px pack plan ironbridge --month 2026-12 --budget 3
```

The budget is a ceiling. The agents propose fewer rules when the catalog has
nothing else that fits the client's telemetry and passes the guardrails.

The Curator reads the coverage and picks from the catalog of upstream rules, a
Platform Engineer agent writes each detection, a Reviewer agent challenges the
result, and code measures the scores, backtests and lab results. It takes
about ten minutes, prints a pull-request link, and puts you back on `main`.
Read the proposal with `./px change show <number>` (add `--diff` for the exact
lines it changes): the description is the
report. The dashboard's Rule packs page shows the same.

The last line of `pack plan` gives the Reviewer's verdict. **If it is `fail`,
do not merge.** The blocker is in the pull request's description. Close the
proposal and ask for a new one:

```bash
./px change close <number> --reason "Reviewer verdict fail: <the blocker>"
./px pack plan ironbridge --month 2026-12 --budget 3
```

When the verdict is `pass`:

```bash
./px change merge <number>                  # the rules deploy in shadow mode
./px pack promote ironbridge-2026.12.0      # later: take them live (--drop PRX-... discards one)
./px change submit "Promote ironbridge-2026.12.0" && ./px change merge <number>
```

## 8. Tune a noisy rule

To see a rule fire, replay its own test events into the client's telemetry.
To simulate a benign pattern that makes it noisy, replay your own event many
times:

```bash
./px lab replay PRX-000002 --client ironbridge                    # its positive test events
./px lab replay PRX-000002 --client ironbridge --file backup-agent.json --repeat 25
```

The file holds one event, or a list of events, in the same shape as a test
event (`./px detection show PRX-000002` prints one). For example:

```json
{
  "event": {"category": ["process"], "type": ["start"], "kind": "event"},
  "host": {"name": "fs-01", "os": {"type": "windows"}},
  "process": {
    "name": "vssadmin.exe",
    "executable": "C:\\Windows\\System32\\vssadmin.exe",
    "command_line": "vssadmin.exe delete shadows /for=D: /oldest /quiet",
    "parent": {"name": "agent.exe", "executable": "C:\\Program Files\\Backup\\agent.exe"}
  }
}
```

Rules run every 5 minutes, so alerts take up to that long to appear. Wait for
them, then let the Tuner agent study them and propose a tested exclusion:

```bash
./px alerts ironbridge --rule PRX-000002 --wait-for 25   # users and hosts show as pseudonyms (id-...)
# it waits up to 8 minutes; --timeout <seconds> changes that
./px tune PRX-000002 --client ironbridge --hint "many alerts from the backup agent"
./px change merge <number>
```

The command and the pull request both state the exclusion in plain words and
the measured impact ("removes 28 of 32 matches over the last 30 days"). The dashboard's Tuning
studio shows a rule's alerts and lets you try an exclusion before proposing it. At any time
afterwards, `./px tuning PRX-000002 --client ironbridge` shows the rule's
exclusions in plain words and how many matches they suppress.

Tuning files can also be written by hand in
`content/clients/<client>/tuning/<rule>.yml`; `docs/agents.md` and the
existing files show the format.

## 9. Hunt

```bash
./px hunt "Akira ransomware precursors on Windows file servers" --clients ironbridge
./px change merge <number>
```

`--sector construction` covers every client in a sector instead. The Hunt
Planner writes hypotheses, runs each query read-only, and records the hit
counts code measured. Hypotheses it marks durable are candidates for step 6 or 7.

## 10. Day to day

| What | Command |
| --- | --- |
| Where does everything stand? | `./px status` |
| Open pull requests | `./px change status`; with a number, that pull request's checks |
| Read one pull request | `./px change show <number>`, with `--diff` for its exact lines |
| Close one without merging | `./px change close <number> --reason "<why>"` |
| Get back to an up-to-date `main` | `./px change home` |
| A client's alerts per rule | `./px alerts ironbridge` |
| Fresh coverage and drift check now | `gh workflow run praxis-nightly.yml` (it also runs every night) |
| Did someone edit a rule in Kibana? | `./px drift ironbridge`. The nightly run puts such edits back and opens an issue |
| What expires soon? | `./px expiry` |
| Give or take away rules | `./px client subscribe ironbridge --pack <pack>` or `--detection <id>`; add `--remove` |
| Retire a rule everywhere | `./px detection deprecate <id>` |
| Add a log source to the data map | `./px source-add <spec file>`; `./px sources` lists what exists |
| Undo a change | Revert its merge: `git revert -m 1 <merge commit>`, then `./px change submit` and `merge` |
| Offboard a client | `./px client offboard ironbridge --yes --delete-space --delete-data`, then `./px change submit` and `merge` |

Offboarding removes the client's rules and keys from the SIEM, and with the
two flags its Kibana space and telemetry. It then checks the SIEM and says
what it verified ("verified in the SIEM: no PRAXIS rules, no active keys, no
Kibana space, no telemetry"); if anything is left it fails and names it. It
cannot be undone.

It names any open pull request that is still for this client, with the command
to close it. It leaves the shared library alone and lists what it kept: the sector's threat
profile, the records of the client's rule packs and hunts (history), and any
detection that no client runs now, with the commands to reassign or retire it.
The client's coverage history stays in the database but no longer shows on
the dashboard or in `./px status`.

## The dashboard

```bash
deploy/dashboard.sh
```

It forwards the dashboard to http://127.0.0.1:3000, opens it, and prints the
sign-in name (`operator`) and password. Use exactly that address: sign-in does
not work at `localhost` or on another port.

`operator` is an administrator and sees everything. To give someone a view of
only some clients, create them a user:

```bash
deploy/remote.sh dashboard-user dana 'a-long-password' --client ironbridge
deploy/remote.sh dashboard-user lee 'another-password' --admin
```

A client-scoped user sees those clients on the Fleet page and nothing else:
rule packs, hunts, audit and settings are for administrators. The same command
changes a password or adds a role. The AI assistant does not use the
dashboard; it works through `./px`.

## Reading coverage

- **Top detection gaps** has a column "in the library": detections for that
  technique that this client does not run yet. Assign one before you write a
  new rule.
- **A silent source** says how many techniques are not visible because of it.
  **A partial source** (too few hosts) keeps its techniques visible at a lower
  score, and says how many rely on it.
- **Visibility gaps** are mostly techniques whose data sources the client does
  not send at all.
- **Alert counts cover 30 days**, so they do not drop when a rule is tuned.
  `./px tuning` shows what a tuning suppresses.
- Events you replay carry their own host names, so a source can show a few
  more hosts than the client has endpoints.

## What PRAXIS does not do yet

These are limits of the product today, not steps you are doing wrong:

- **Telemetry in the lab is synthetic.** Collection from real endpoints
  (Fleet Server and Elastic Agent) is not part of the stack yet.
- **One SIEM connection.** The server scripts assume the bundled Elastic,
  named `lab`. A second, remote SIEM has not been set up or tested, because
  there is no second SIEM here to test against.
- **An offboarded client cannot be checked again later.** Offboarding verifies
  the SIEM itself and prints the result, but once the client is out of the
  content PRAXIS no longer knows its space or keys, so there is no later
  re-check. Keep the offboarding output as the record.
- **No command removes a sector profile or a rule-pack record.** They are
  shared history and harmless without a client.
- **Elastic and EQL only.** Splunk, Sentinel and ES|QL rules come later.
  Exclusions match case-sensitively, which is how Kibana exception lists work.

## If something fails

| Symptom | What to do |
| --- | --- |
| `error ...` naming a file or field | The message says what is wrong; fix that field and repeat |
| A check fails on "packs.lock" | Run `./px lock`, then `./px change submit` again |
| "Lab staging" fails | `./px lab test <id>` shows which case fired or stayed quiet wrongly |
| `the working tree has uncommitted changes` | Agent commands start from a clean `main`: submit or discard your changes first |
| `you are on branch ...` | Run `./px change home`, then repeat the command |
| `no ChatGPT credential` | Sign in on the dashboard's Settings page (`deploy/dashboard.sh`) |
| `the ChatGPT plan's usage limit is reached` | Wait; see https://chatgpt.com/settings/usage |
| `./px` cannot reach the server | Check `PRAXIS_SERVER` in `.env` and that `ssh` to it works without a password |
