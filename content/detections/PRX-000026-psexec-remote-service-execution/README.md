# PRX-000026 PsExec client or service binary started

## Summary

Fires when the PsExec client or the PsExec service binary starts on a Windows host. Ransomware crews use PsExec to move between hosts and to push their payload.

## How it works

The query looks at Windows process starts. It matches the PsExec client and the PSEXESVC service binary by process name. It also matches the original PE file name, so a renamed copy still matches. The client shows the source host and the service binary shows the target host.

## Blind spots and known gaps

- PsExec clones that use another service name, such as Impacket or PAExec, are not matched.
- A copy with a changed name and stripped PE metadata is not matched.
- Other remote execution paths (WMI, WinRM, scheduled tasks) need their own rules.

## SOC triage

1. Identify the user and check that the account is an administrator who uses PsExec.
2. Read the client command line for the target host and the command it ran.
3. On the target, review the child processes of the service binary.
4. Count the hosts with this alert in the last hour; many hosts means lateral movement.

## Tuning history

None yet.
