---
platform: elastic
source: logs-endpoint.events.registry
name: Elastic Defend registry events
data_components:
  Windows Registry Key Modification: [registry.path, registry.data.strings, process.name]
sample:
  event: {category: [registry], type: [change], kind: event}
  host: {os: {type: windows}}
  user: {name: j.doe}
  process: {name: OneDriveSetup.exe, pid: 3012, executable: 'C:\Program Files\Microsoft OneDrive\OneDriveSetup.exe'}
  registry:
    hive: HKEY_USERS
    path: 'HKEY_USERS\S-1-5-21-1004\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive'
    value: OneDrive
    data: {strings: ['"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background']}
---
## What it is

Registry value changes on Windows hosts from Elastic Defend, with the process
that wrote them. Windows only.

## Useful queries

- Run key changes: `registry where registry.path : "*\\CurrentVersion\\Run\\*"`
- Service image path changes: `registry where registry.path : "*\\Services\\*\\ImagePath"`

## Analyst notes

- Elastic Defend only reports a curated set of registry paths, not every write.
  A persistence location outside that set will not appear here.
