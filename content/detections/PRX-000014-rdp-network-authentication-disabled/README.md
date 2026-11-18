# PRX-000014 RDP network authentication disabled

## Summary

Detects registry writes that disable Network Level Authentication for the RDP listener. Attackers can use this change to reach the sign-in screen before authentication. The alert does not prove an RDP connection occurred.

## How it works

The query selects Windows registry creation and change events. It matches the complete UserAuthentication path under the RDP-Tcp listener and requires zero data in decimal or hexadecimal form. Paths include CurrentControlSet and numbered control sets under three registry root formats. Matching ignores case. The query does not depend on the writer process, so renamed tools and direct API writes remain detectable. The complete path makes a separate registry value condition unnecessary.

## Blind spots and known gaps

The rule requires registry events with a complete path and data in registry.data.strings. It misses policy paths, other listeners, missing telemetry, and other zero representations. ControlSet??? accepts any three characters. A write can repeat an existing value without changing protection. The rule cannot establish effective policy, listener reachability, successful access, or malicious intent.

## SOC triage

1. Identify the host, account, writer process, and parent process in the registry event.
2. Confirm the current UserAuthentication value and effective RDP policy on the host.
3. Check the change ticket with the host owner.
4. Review nearby remote logons, source addresses, and changes to accessibility programs.
5. Escalate unexplained changes for investigation.
6. Preserve the evidence before approved containment or restoration.

## Tuning history

None yet.
