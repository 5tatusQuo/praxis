# PRX-000021 Administrative share mounted with net use

## Summary

Fires when net.exe or net1.exe maps a hidden administrative share on a remote host. Attackers use these shares to copy tools and run them on other machines.

## How it works

The query looks at Windows process starts. It matches net.exe and net1.exe by name or by original PE file name, so a renamed copy still matches. The command line must contain the use verb. It must also contain a UNC path to ADMIN$ or to the C$, D$ or E$ drive share.

## Blind spots and known gaps

- Lateral movement over SMB by other tools or direct API calls does not start net.exe.
- Hosts that do not log command lines are invisible to this rule.
- The IPC$ share and drive shares beyond E$ are not matched.
- The rule does not confirm that the connection succeeded.

## SOC triage

1. Identify the user, the source host and the remote host in the command line.
2. Check the parent process for a script, a remote shell or an interactive session.
3. Ask whether the account is an administrator with a reason to map that share.
4. Look for files copied to the share and services or tasks created on the remote host.
5. Escalate if the account or the source host is not an approved administration point.

## Tuning history

None yet.
