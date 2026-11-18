# PRX-000002 Volume shadow copies deleted or resized with built-in tools

## Summary

Fires when a built-in Windows tool deletes volume shadow copies or shrinks the
space reserved for them. Ransomware operators do this shortly before encrypting
a host, so that files cannot be restored from local snapshots.

## How it works

The query looks at Windows process-start events and matches four tools, each by
process name or by original PE file name so a renamed copy still matches:

- `vssadmin.exe` with `delete shadows`, or with `resize shadowstorage`, which
  forces Windows to discard snapshots by shrinking their storage.
- `wmic.exe` with `shadowcopy delete`.
- `powershell.exe` or `pwsh.exe` with `Win32_ShadowCopy` followed by a delete
  call (`.Delete()`, `Remove-WmiObject`, `Remove-CimInstance`).
- `diskshadow.exe` with `delete shadows` on its command line.

It needs process creation events with full command lines: Elastic Defend
process events or Sysmon event ID 1.

## Blind spots and known gaps

- Deleting snapshots through the VSS COM API or `DeviceIoControl` directly, as
  some ransomware families do, starts no child process and is not seen.
- `diskshadow.exe /s script.txt` hides the delete command inside the script.
- Encoded PowerShell (`-enc`) hides `Win32_ShadowCopy` from the command line.
- Other recovery inhibitors (`bcdedit`, `wbadmin delete catalog`) are separate
  behaviours and need their own detections.

## SOC triage

1. Identify the user and parent process. A scheduled backup job running as a
   service account on a server is expected; an interactive shell, an Office
   application or a remote-execution service as parent is not.
2. Check how many hosts ran the same command in the last hour. Several hosts at
   once means ransomware staging: escalate immediately.
3. Look on the host for what usually comes next: `bcdedit` recovery changes,
   services being stopped in bulk, mass file renames or new ransom notes.
4. If it is not a known backup or maintenance job, isolate the host first and
   investigate after. Minutes matter at this stage.

## Tuning history

None yet.
