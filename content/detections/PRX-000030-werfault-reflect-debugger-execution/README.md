# PRX-000030 WerFault ReflectDebugger execution

## Summary

Detects WerFault starting with the -pr option. An attacker can use this option to execute a program through the ReflectDebugger registry value.

## How it works

The query checks Windows process starts. It identifies WerFault by its process name or original PE file name. It matches the -pr argument or a separate -pr token in the command line. The command line check accepts spaces, tabs, quoted tokens, and a final token without trailing whitespace.

## Blind spots and known gaps

The event does not prove that the ReflectDebugger value exists or that its program executes. Missing arguments and command lines prevent detection. Renamed copies need original PE metadata. Unusual quoting can evade the command line check. The rule does not detect registry changes.

## SOC triage

1. Check the parent process, user, and command line.
2. Inspect the ReflectDebugger value under the Windows Error Reporting registry keys.
3. Check the referenced program, its signature, and its origin.
4. Review child processes and recent registry changes on the host.
5. Confirm any debugger configuration with the system owner.

## Tuning history

None yet.
