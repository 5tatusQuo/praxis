# PRX-000001 LSASS memory dump via comsvcs.dll MiniDump

## Summary

Fires when `rundll32.exe` is started with a command line that calls the
`MiniDump` export of `comsvcs.dll`, by name or by ordinal. Attackers use this
built-in Windows library to dump the memory of `lsass.exe` and extract
credentials offline, with no extra tooling on disk.

## How it works

The query looks at Windows process-start events. It matches a process that is
`rundll32.exe` by name, or by its original PE file name so a renamed copy still
matches. The command line must mention `comsvcs` followed by the export, which
attackers write in several ways: `MiniDump`, the ordinal `#24`, `#+24`, or a
negative ordinal such as `#-4294967272` that wraps round to 24.

It needs process creation events with full command lines: Elastic Defend
process events or Sysmon event ID 1.

## Blind spots and known gaps

- A copy of `comsvcs.dll` under another file name is not matched, because the
  command line then no longer contains `comsvcs`.
- Calling `MiniDumpWriteDump` directly (procdump, custom loaders, Task Manager)
  is out of scope; it needs process-access telemetry (Sysmon event ID 10).
- Hosts that do not log command lines are invisible to this rule.
- The rule does not check that the target PID is LSASS, so it also fires on a
  dump of another process. That is rare and still worth a look.

## SOC triage

1. Read the command line: the number after `MiniDump` is the target PID and the
   path after it is the dump file. Confirm the PID was `lsass.exe` on that host.
2. Check the parent process and user. An interactive shell, a script host or a
   remote-execution service (WMI, PsExec, WinRM) as parent points to an attacker.
3. Look for the dump file being read, archived or copied off the host afterwards.
4. If confirmed: isolate the host, treat every account logged on to it as
   compromised, and reset those credentials.

## Tuning history

- 2026-11: `acme` excludes its imaging support agent, which dumps its own
  process through comsvcs after a viewer crash (client tuning, expires 2027-05).
- 2026-11: `globex` raises severity to critical and runs the rule every minute.
- v2: documented vendor support agents as a known false positive.
