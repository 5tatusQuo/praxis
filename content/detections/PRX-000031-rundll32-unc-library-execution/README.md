# PRX-000031 Rundll32 executes a UNC library

## Summary

The rule detects Rundll32 commands that contain UNC paths. Attackers can load a remote library through this Windows utility to execute code.

## How it works

The query checks Windows process starts from Elastic Defend or Sysmon. It identifies Rundll32 by its process name or original PE name, which also detects renamed copies. It matches UNC paths after spaces or tabs, including quoted paths. It excludes commands that contain a local named pipe path. It does not require a library extension because remote libraries can use other extensions.

## Blind spots and known gaps

Missing command lines prevent matches. Renamed copies need the original PE name. Mapped drives and other path forms can escape detection. The named pipe exclusion can hide a command with an added pipe argument. A UNC argument does not prove that Windows loaded a remote library or used SMB. Network and library events must confirm that activity.

## SOC triage

1. Identify the UNC path and determine whether it names the library or another argument.
2. Check the parent process and user for an approved reason to run the command.
3. Inspect the remote file, its signature, and the share owner.
4. Check network events for SMB connections and library events for a successful load.
5. Review child processes and nearby authentication events for lateral movement.
6. Isolate the host if the evidence confirms malicious execution.

## Tuning history

None yet.
