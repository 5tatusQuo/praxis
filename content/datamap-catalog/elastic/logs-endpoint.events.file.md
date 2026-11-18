---
platform: elastic
source: logs-endpoint.events.file
name: Elastic Defend file events
data_components:
  File Creation: [file.path, file.name, process.name, user.name]
  File Modification: [file.path, process.name]
sample:
  event: {category: [file], type: [creation], kind: event}
  host: {os: {type: windows}}
  user: {name: j.doe}
  process: {name: winword.exe, pid: 7788, executable: 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE'}
  file: {path: 'C:\Users\j.doe\Documents\notes.docx', name: notes.docx, extension: docx}
---
## What it is

File creation, modification, rename and deletion events from Elastic Defend,
with the process responsible.

## Useful queries

- Executables dropped by Office: `file where event.type == "creation" and file.extension : ("exe", "dll") and process.name : "winword.exe"`
- Mass renames by one process over a short window (ransomware staging).

## Analyst notes

- Very high volume on file servers; some policies exclude paths. An excluded
  path is a blind spot that this source cannot show you.
