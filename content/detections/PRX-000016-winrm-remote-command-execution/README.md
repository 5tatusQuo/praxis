# PRX-000016 Remote command execution over Windows Remote Management

## Summary

Fires when winrs.exe runs a command on a remote host, or when the WinRM remote shell host starts a command shell. Attackers use WinRM to move between Windows machines with stolen accounts.

## How it works

The query looks at Windows process starts. On the source host it matches winrs.exe, by name or original PE file name, with a remote target option. On the target host it matches cmd.exe or PowerShell started by winrshost.exe, the process that serves winrs sessions.

## Blind spots and known gaps

- PowerShell remoting (Enter-PSSession, Invoke-Command) uses wsmprovhost.exe and is not matched.
- WinRM clients that do not start winrs.exe, such as scripts and attack tools, are seen only on the target.
- Hosts that do not log process starts are invisible to this rule.

## SOC triage

1. Identify the user, the source host and the target named in the command line.
2. Check whether that user normally administers the target host.
3. Read the remote command and look for discovery, credential or download activity.
4. Check the source host for earlier alerts or unusual logons.
5. If it is not known administration, isolate both hosts and reset the account.

## Tuning history

None yet.
