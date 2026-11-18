---
platform: elastic
source: logs-system.security
name: Windows Security event log (logons)
data_components:
  Logon Session Creation: [user.name, source.ip, event.outcome]
  User Account Authentication: [user.name, event.outcome]
sample:
  event: {category: [authentication], type: [start], kind: event, code: "4624", outcome: success}
  host: {os: {type: windows}}
  user: {name: j.doe, domain: CORP}
  source: {ip: 10.20.4.17}
  winlog: {channel: Security, logon: {type: Network}}
---
## What it is

The Windows Security channel collected by the System integration: logons
(4624), failed logons (4625), explicit-credential logons (4648) and logoffs.

## Useful queries

- Failed logons by source: `authentication where event.outcome == "failure"` grouped by `source.ip`.
- Network logons by an admin account to many hosts within an hour.

## Analyst notes

- `source.ip` is empty for local and service logons, so its population is never
  100%. A sharp drop still means an audit-policy or parsing problem.
- Usually collected from servers and domain controllers first; workstation
  coverage is often partial.
