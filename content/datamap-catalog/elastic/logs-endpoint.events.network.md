---
platform: elastic
source: logs-endpoint.events.network
name: Elastic Defend network events
data_components:
  Network Connection Creation: [destination.ip, destination.port, source.ip, process.name]
sample:
  event: {category: [network], type: [start], kind: event}
  host: {os: {type: windows}}
  user: {name: j.doe}
  process: {name: chrome.exe, pid: 4321, executable: 'C:\Program Files\Google\Chrome\Application\chrome.exe'}
  source: {ip: 10.20.4.17, port: 51544}
  destination: {ip: 142.250.70.14, port: 443}
  network: {transport: tcp, direction: egress}
---
## What it is

Connection attempts and accepts seen by Elastic Defend on the host, tied to the
process that made them. Unlike firewall or flow logs, every event names a process.

## Useful queries

- Outbound from a script host: `network where process.name : ("wscript.exe", "mshta.exe")`
- Rare destination ports per process: aggregate `destination.port` by `process.name`.

## Analyst notes

- High volume. Elastic Defend can be set to drop network events; check the
  policy before assuming a host made no connections.
- DNS questions are in a separate dataset, not here.
