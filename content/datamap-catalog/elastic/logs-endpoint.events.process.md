---
platform: elastic
source: logs-endpoint.events.process
name: Elastic Defend process events
data_components:
  Process Creation: [process.name, process.executable, process.command_line, process.parent.name, user.name]
  Command Execution: [process.command_line, user.name]
sample:
  event: {category: [process], type: [start], kind: event}
  host: {os: {type: windows}}
  user: {name: j.doe}
  process:
    name: chrome.exe
    pid: 4321
    executable: 'C:\Program Files\Google\Chrome\Application\chrome.exe'
    command_line: '"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer'
    pe: {original_file_name: chrome.exe}
    parent: {name: chrome.exe, executable: 'C:\Program Files\Google\Chrome\Application\chrome.exe'}
---
## What it is

Process start and end events from the Elastic Defend endpoint integration, one
document per event, in ECS. This is the main source for behaviour detections on
Windows, macOS and Linux hosts.

## Useful queries

- Starts of one binary: `process where event.type == "start" and process.name : "rundll32.exe"`
- Children of Office: `process where process.parent.name : ("winword.exe", "excel.exe")`

## Analyst notes

- `process.command_line` is the field most detections depend on. If its
  population drops, command-line collection was probably turned off in the policy.
- `process.pe.original_file_name` survives a rename of the binary; prefer it over
  `process.name` when hunting for renamed tools.
