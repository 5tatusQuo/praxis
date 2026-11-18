# Runbook: onboard a client and run it

This is the whole life of one client, in order, as an operator does it today.
Every command here was run against the reference deployment. The example
client is `ironbridge`, a fictional construction firm; replace the name and
sector with your own.

Where the system is rough, the step says so under **Rough spot**. Those are
known gaps, not mistakes on your side.

## Rules that apply throughout

- **Never use a real client name, hostname or credential in this repo.** It is
  public. `client.yml` must say `fictional: true`.
- **Every change is a pull request.** `main` is protected. Merging is what
  deploys.
- **You review and merge what agents propose.** Agent branches start with `ai/`.
- Commands that start with `deploy/` run on your workstation, from the repo
  root. They reach the server named in `.env` (`PRAXIS_SERVER=user@host`).

## Before you start

On your workstation: `git`, the GitHub CLI (`gh`, logged in), and
[uv](https://docs.astral.sh/uv/). Then:

```bash
git checkout main && git pull
uv sync
uv run praxis validate          # expect: ok N detections, ...
deploy/dashboard.sh             # opens http://127.0.0.1:3000; leave it running in its own terminal
```

For the agent steps (7, 9, 10): open **Settings** in the dashboard and check
that it says you are signed in with ChatGPT.

Three ways to run `praxis`, and when to use each:

| Form | Use it for |
| --- | --- |
| `uv run praxis ...` | Anything that only reads or writes files: `validate`, `lock`, `render`, `pack promote` |
| `deploy/with-server.sh uv run praxis ...` | Anything that reads the SIEM or the database, or runs an agent: `lab`, `coverage`, `pack plan`, `tune`, `hunt`. It carries read and lab keys only |
| `deploy/remote.sh run '...'` | The two steps that need admin or deploy keys, which never leave the server: provisioning and the connection check |

## 1. Create the client

Start a branch and add three files.

```bash
git checkout -b onboard-ironbridge
mkdir -p content/clients/ironbridge/lab
```

**`content/clients/ironbridge/client.yml`** is the client's manifest:

```yaml
id: ironbridge                  # lower case, letters, digits and hyphens; must match the folder
name: Ironbridge Construction (fictional)
sector: construction            # must match a file in content/threat-profiles/
fictional: true                 # required
assets:
  endpoints: 40                 # hosts you expect to report; host coverage is measured against it
platforms:
  elastic:
    connection: lab             # which SIEM connection to use; the bundled Elastic is `lab`
    space: ironbridge           # Kibana space for this client's rules; letters, digits, underscores
    namespace: ironbridge       # data-stream namespace of this client's logs; same character rules
packs:
  - baseline                    # standing packs the client subscribes to
```

**`content/threat-profiles/construction.yml`** says which threat actors
matter to the sector. Gaps are ranked by how many of these groups use each
technique. Skip this file only if the sector already has one.

```yaml
sector: construction
description: >-
  Ransomware crews that have hit construction and engineering firms, plus one
  state-linked group with a record of stealing engineering data. An example to
  replace with your own intelligence.
groups:                         # MITRE ATT&CK group ids, from https://attack.mitre.org/groups/
  - G1024  # Akira
  - G1032  # INC Ransom
  - G0096  # APT41
techniques:                     # optional extra weight, 0 to 1, for what you see in your own cases
  T1490: 0.3
references:
  - https://attack.mitre.org/groups/
```

**`content/clients/ironbridge/lab/telemetry.yml`** describes synthetic
telemetry, because the lab has no real agents. List every log source the
client's rules need.

```yaml
sources:
  - source: logs-endpoint.events.process     # must have a note in content/datamap-catalog/elastic/
    hosts: 40                                # how many hosts report to this source
    events_per_day: 300
  - source: logs-endpoint.events.registry
    hosts: 40
    events_per_day: 150
  - source: logs-system.security
    hosts: 25                                # 25 of 40: partial coverage, on purpose
    events_per_day: 200
```

Check and pin:

```bash
uv run praxis validate          # must say ok
uv run praxis lock              # writes content/clients/ironbridge/packs.lock
uv run praxis render --client ironbridge
```

**Rough spots**

- There is no `praxis client add`; the files are written by hand.
- Sources available today: `logs-endpoint.events.process`, `.network`,
  `.file`, `.registry`, and `logs-system.security`. Another source needs a
  schema note in `content/datamap-catalog/elastic/` first.
- The `baseline` pack needs process and registry events. A rule whose sources
  are all missing may fail the deploy's smoke check in step 4.

## 2. Connect the client to the SIEM

Provisioning creates the Kibana space and three scoped API keys (lab, read,
deploy). It needs the admin identity, which exists only on the server, so the
server needs your new files first.

```bash
deploy/remote.sh sync
deploy/remote.sh run 'export PATH=$HOME/.local/bin:$PATH; . deploy/server/env.sh admin && uv run praxis admin provision ironbridge --env-out /opt/praxis/keys.env && deploy/server/publish-keys.sh'
deploy/remote.sh up full        # restarts the API so it picks up the new read key
```

Expect `wrote 2 keys to /opt/praxis/keys.env`, then
`wrote /etc/praxis/deploy/ironbridge.env`.

Now prove both identities work, and that the read identity cannot write:

```bash
deploy/remote.sh run 'export PATH=$HOME/.local/bin:$PATH; . deploy/server/env.sh && uv run praxis connection ironbridge'
```

Expect `ok` for `read` (with "write correctly refused") and `ok` for `deploy`.

**Rough spots**

- `deploy/remote.sh sync` copies your working tree to the server, uncommitted
  changes included. That is how the server sees a client that is not merged yet.
- Run through `deploy/with-server.sh`, the connection check reports the deploy
  identity as failed. That is expected: deploy keys never leave the server.
- Running `provision` twice does nothing the second time. `--rotate` replaces
  the keys; then run `publish-keys.sh` and `deploy/remote.sh up full` again.
- The scripts assume one SIEM connection named `lab`. A second connection
  needs edits to `deploy/server/env.sh`, `publish-keys.sh`,
  `deploy/with-server.sh` and the CD workflow.

## 3. Give the client telemetry

```bash
deploy/with-server.sh uv run praxis lab seed ironbridge
```

Expect one line per source, for example
`ironbridge: logs-endpoint.events.process +4200 events`. It writes 14 days of
events. The nightly workflow tops it up from then on.

**Rough spot:** this is synthetic. With real clients, telemetry comes from
their own agents; Fleet and Elastic Agent are not part of the stack yet.

## 4. Deploy the baseline

```bash
git add -A && git commit -m "Onboard ironbridge"
git push -u origin onboard-ironbridge
gh pr create --fill
gh pr checks --watch            # four checks; "Lab staging" replays every test event in the lab SIEM
gh pr merge --merge --delete-branch
git checkout main && git pull
gh run watch                    # pick the praxis-cd run
```

Merging runs CD. For each client it deploys the rendered rules, waits for each
rule's first run, and stores a coverage snapshot. In the log, expect
`created` for each of the client's rules and `succeeded` for each smoke check.

Check the result in three places:

- Kibana, space `ironbridge`, Security → Rules: the rules are there, enabled,
  tagged `PRAXIS`.
- The dashboard's Fleet page: `ironbridge` has a row.
- `deploy/with-server.sh uv run praxis drift ironbridge` says the SIEM matches
  `packs.lock`.

**Rough spot:** the first deploy of a new client creates a GitHub environment
named `client-ironbridge` by itself. Add required reviewers to it in the
repository settings if you want a second approval before deploys.

## 5. Read the coverage

Open the client in the dashboard, or:

```bash
deploy/with-server.sh uv run praxis coverage ironbridge
```

You get the visibility score per data component, the status of each rule, and
the top detection gaps ranked by threat weight. `docs/visibility-scoring.md`
explains every number. `--out <folder>` also writes the snapshot, an ATT&CK
Navigator layer and `tables.csv`.

Expect most techniques to be detection gaps: the client can see process
activity but has three rules. That list is what steps 6 and 7 work from.

## 6. Add a rule by hand

A detection is a folder. The next free id is one above the highest in
`content/detections/`.

```
content/detections/PRX-000007-certutil-remote-download/
  detection.yml             metadata
  README.md                 five sections, in this order
  elastic.eql               the query; it must not name indices
  tests/positive/*.json     events that must fire
  tests/negative/*.json     benign look-alikes that must stay quiet
```

**`detection.yml`**

```yaml
id: PRX-000007
name: Certutil used to download a file
intent: >-
  Detects certutil fetching a file from a URL, a built-in way to bring tools
  onto a host without a browser or PowerShell.
version: 1
lifecycle: staged               # staged = shadow mode; production = alerts reach the SOC
owner: detection-engineering
severity: medium                # low, medium, high or critical
risk_score: 47                  # 0 to 100
attack:
  - technique: T1105
    tactic: TA0011              # the technique must belong to this tactic
data_components:
  - Process Creation            # an ATT&CK data component name
pyramid_tier: ttp               # hash, ip, domain, artifact, tool or ttp
log_sources:
  elastic:
    indices:
      - logs-endpoint.events.process-*    # must end in -*; the client's namespace replaces the *
schedule:
  interval: 5m
  lookback: 6m
provenance:
  source: praxis
  licence: Apache-2.0
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
false_positives:
  - Administrators who fetch certificates or revocation lists by hand.
```

**`elastic.eql`**

```
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "certutil.exe" or ?process.pe.original_file_name : "CertUtil.exe") and
  process.command_line : ("*urlcache*", "*verifyctl*") and
  process.command_line : ("*http://*", "*https://*", "*ftp://*")
```

**`README.md`** must have exactly these headings. The title starts with the id.

```markdown
# PRX-000007 Certutil used to download a file

## Summary
## How it works
## Blind spots and known gaps
## SOC triage
## Tuning history
```

Each section needs real text (40 characters or more, except Tuning history,
which can say "None yet."). Copy an existing README for the style.

**A test event** is one ECS document, or a list of them in order:

```json
{
  "event": {"category": ["process"], "type": ["start"], "kind": "event"},
  "host": {"name": "ws-lab-07", "os": {"type": "windows"}},
  "user": {"name": "j.doe"},
  "process": {
    "name": "certutil.exe",
    "executable": "C:\\Windows\\System32\\certutil.exe",
    "command_line": "certutil.exe -urlcache -split -f http://example.invalid/tool.exe C:\\Users\\Public\\tool.exe",
    "pe": {"original_file_name": "CertUtil.exe"},
    "parent": {"name": "cmd.exe"}
  }
}
```

Give the client the rule, either for this client only (add a `detections:`
list to its `client.yml`) or for everyone (add the id to
`content/content-packs/baseline.yml`):

```yaml
detections:
  - PRX-000007
```

Then test and ship:

```bash
uv run praxis validate
deploy/with-server.sh uv run praxis lab test PRX-000007   # every row must say pass
uv run praxis lock
# branch, commit, push, pull request, merge: as in step 4
```

A `staged` rule deploys in shadow mode: named `[shadow] ...`, lowest severity,
tagged `praxis-shadow`, and it gives no coverage yet. To take it live, change
`lifecycle: staged` to `production`, run `uv run praxis lock`, and open
another pull request.

**Rough spots**

- A changed query must come with a changed "How it works" section, or CI fails.
- Only EQL is supported. Elastic exclusions are case-sensitive.

## 7. Have the agents propose a pack

The Curator reads the client's coverage, picks rules from the catalog of
upstream detections, a Platform Engineer agent writes each one, and a Reviewer
agent challenges the result.

```bash
git checkout main && git pull           # the working tree must be clean
deploy/with-server.sh uv run praxis pack plan ironbridge --month 2026-12 --budget 3
```

It takes several minutes and prints a pull-request link. It leaves you on the
agent's branch, so run `git checkout main` afterwards. Review the pull request
(the description is the report) or the dashboard's Rule packs page, then merge
it yourself. The rules deploy in shadow mode.

When you are satisfied with them:

```bash
git checkout main && git pull && git checkout -b promote-ironbridge-2026-12
uv run praxis pack promote ironbridge-2026.12.0        # add --drop PRX-0000NN for a rule to discard
git add -A && git commit -m "Promote ironbridge-2026.12.0" && git push -u origin HEAD
gh pr create --fill
```

**Rough spots**

- Model calls draw on the ChatGPT plan you signed in with.
- If no pick survives the guardrails and tests, the command says so and opens
  nothing.
- The catalog is rebuilt with `deploy/with-server.sh uv run praxis catalog sync`.
  Do that after changing `content/sources.yml`.

## 8. Tune a noisy rule

In the dashboard, open the client, then a rule: the **Tuning studio** shows
the rule's alerts grouped by field, and lets you try an exclusion and see what
it removes before you propose anything.

To have the Tuner agent propose one:

```bash
git checkout main && git pull
deploy/with-server.sh uv run praxis tune PRX-000002 --client ironbridge --hint "what you noticed"
```

Or write `content/clients/ironbridge/tuning/PRX-000002.yml` by hand:

```yaml
rule: PRX-000002
reason: The backup agent prunes old shadow copies after each nightly backup.
evidence: ["ALERT-2310", "SOC-91"]          # required for an exclusion
author: human:your-name
expires: 2027-05-31                         # reviewed again when it expires
exclude:
  - field: process.parent.executable
    op: equals                              # equals, in, startswith, endswith, contains, wildcard
    value: 'C:\Program Files\Backup\agent.exe'
    also:                                   # conditions that must ALL match too
      - field: process.command_line
        op: contains
        value: '/oldest'
examples:                                   # required: an event the exclusion must silence
  - event: {category: [process], type: [start]}
    host: {os: {type: windows}}
    process:
      name: vssadmin.exe
      command_line: 'vssadmin.exe delete shadows /for=D: /oldest /quiet'
      parent: {executable: 'C:\Program Files\Backup\agent.exe'}
```

Separate entries under `exclude` are alternatives: each one alone suppresses
alerts. To narrow an exclusion, add to `also`. Other operations in the same
file: `severity` with `risk_score`, `schedule`, and `enabled: false` (which
needs `expires`).

Then `uv run praxis validate`, `deploy/with-server.sh uv run praxis lab test PRX-000002`,
`uv run praxis lock`, and a pull request. The lab checks that the example
fires without the tuning and is silent with it, and that every positive test
still fires.

## 9. Hunt

```bash
git checkout main && git pull
deploy/with-server.sh uv run praxis hunt "Akira ransomware precursors on Windows file servers" --clients ironbridge
```

Use `--sector construction` instead to cover every client in a sector. The
Hunt Planner writes hypotheses, runs each query read-only, and opens a pull
request with the hunt record. The dashboard's Hunts page shows it. Hypotheses
it marks durable are candidates for step 6 or 7.

## 10. Day to day

| What | How |
| --- | --- |
| Fresh coverage and drift check | The `praxis-nightly` workflow, every night. Run it now: `gh workflow run praxis-nightly.yml` |
| Did someone edit a rule in Kibana? | `deploy/with-server.sh uv run praxis drift ironbridge` |
| What expires soon? | `uv run praxis expiry` |
| Undo a change | Revert its merge in a pull request: `git revert -m 1 <merge commit>`. Merging the revert redeploys the previous rules |
| Agent activity | The dashboard's Audit page |

**Rough spots**

- Nightly drift fails the job when it finds a difference. It does not yet fix
  it or open a pull request.
- There is no offboarding command. Removing a client's folder stops deploys,
  but leaves its rules, space and keys in the SIEM.
- The dashboard has no login of its own. Anyone with SSH access to the server
  can reach it.

## If something fails

| Symptom | Likely cause |
| --- | --- |
| `praxis validate` names a file and a field | Read the message; fields not in the schema are rejected |
| CI fails on "packs.lock pins exactly what would deploy" | Run `uv run praxis lock` and commit the result |
| CI "Lab staging" fails | A positive test did not fire or a negative one did; run `praxis lab test <id>` to see which |
| CD smoke check says `timeout` or `partial failure` | The rule's data streams do not exist for this client; seed telemetry (step 3) and re-run the workflow |
| `environment variable PRAXIS_ELASTIC_LAB_..._API_KEY is not set` | You ran a SIEM command without `deploy/with-server.sh`, or one that needs the server (step 2) |
| `the working tree has uncommitted changes` | Agent commands need a clean tree on `main` |
| `no ChatGPT credential` | Sign in again on the dashboard's Settings page |
| `the ChatGPT plan's usage limit is reached` | Wait, or check https://chatgpt.com/settings/usage |
