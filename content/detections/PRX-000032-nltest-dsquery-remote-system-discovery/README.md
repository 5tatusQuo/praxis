# PRX-000032 Domain controllers or computers enumerated with nltest or dsquery

## Summary

Fires when nltest.exe lists domain controllers or dsquery.exe lists computers or servers. Attackers run these built-in tools to map a domain before lateral movement.

## How it works

The query looks at Windows process starts. It matches nltest.exe and dsquery.exe by name or by original PE file name, so a renamed copy still matches. For nltest the command line must contain dclist or dsgetdc. For dsquery the command line must ask for computer or server objects.

## Blind spots and known gaps

- Enumeration with net view, PowerShell or LDAP tools needs its own rules.
- Hosts that do not log command lines are invisible to this rule.
- The rule does not confirm that the enumeration succeeded.

## SOC triage

1. Identify the user, the host and the parent process.
2. Check whether the user is a domain administrator doing planned work.
3. Look for other discovery commands from the same host in the hour around it.
4. Check for new remote logons from that host afterwards.
5. Escalate if the user or host has no reason to map the domain.

## Tuning history

None yet.
