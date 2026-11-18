# PRX-000028 Program compatibility assistant used for execution

## Summary

Detects the Windows compatibility assistant starting with the -a execution option. Attackers can use this trusted utility to start programs indirectly and bypass application controls.

## How it works

The query checks Windows process starts. It identifies pcalua.exe by its process name or original PE file name to detect renamed copies. The command line must contain -a after a space or tab. The match allows attached arguments and ignores letter case. It detects an execution attempt, not successful execution.

## Blind spots and known gaps

Missing command lines prevent detection. Renamed copies need the original PE file name. Changed PE metadata can defeat that check. Other indirect execution tools need separate detections. Approved compatibility tasks can also match. The query does not confirm that application controls were bypassed.

## SOC triage

1. Identify the target program and arguments after -a.
2. Check the parent process and user for an approved administrative task.
3. Inspect the target file, signature, and origin.
4. Review child processes to confirm execution.
5. Isolate the host if the target or subsequent activity is malicious.

## Tuning history

None yet.
