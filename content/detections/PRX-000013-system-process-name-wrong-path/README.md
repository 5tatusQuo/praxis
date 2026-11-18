# PRX-000013 Windows system process name running from an unusual path

## Summary

Fires when a process named like a core Windows system process starts from a folder outside the Windows system directories. Attackers name malware this way so it blends into process lists.

## How it works

The query looks at Windows process starts. It matches ten core system process names, such as svchost.exe and lsass.exe. The executable path must be present. It must not sit under System32, SysWOW64 or WinSxS on any drive.

## Blind spots and known gaps

- Malware that uses any other legitimate-looking name is not matched.
- A malicious file written into System32 itself is not matched.
- Events without an executable path are ignored.

## SOC triage

1. Read the full executable path and check who wrote the file there.
2. Check the file hash and its signature against the real Windows binary.
3. Review the parent process, the user and the command line.
4. Isolate the host if the file is unsigned or unknown.

## Tuning history

None yet.
