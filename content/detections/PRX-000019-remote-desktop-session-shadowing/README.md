# PRX-000019 Potential Remote Desktop Shadowing Activity

## Summary

Detects Windows desktop shadowing through policy changes or process starts. Attackers can use shadowing to observe or control another user's session. An alert does not prove unauthorized access.

## How it works

The query matches changes to the Terminal Services Shadow policy with values 1 through 4, in decimal or hexadecimal form. It also matches mstsc with a shadow argument, or either shadow helper under svchost. Process names and original PE names identify the binaries, including renamed copies. Matches ignore case. The exact registry path identifies the value without a separate value-name check. Values 1 and 3 require consent. Values 2 and 4 permit shadowing without consent.

## Blind spots and known gaps

Missing process arguments or registry data can prevent matches. Renamed binaries need original PE metadata. Helper detection requires the parent name svchost.exe. Other registry locations, data formats, and custom shadowing tools can evade detection. Policy changes do not prove an active session. Process starts do not prove a successful connection. Authorized support sessions also match.

## SOC triage

1. Identify the matched process or registry change.
2. Inspect the account, executable path, signature, parent process, and arguments.
3. Check the Shadow value and consent mode.
4. Verify the support ticket and session owner authorization.
5. Correlate remote logons and nearby session enumeration with the same account and host.
6. Preserve the process tree and registry evidence before containment.
7. Escalate unexplained shadowing, especially activity without consent.

## Tuning history

None yet.
