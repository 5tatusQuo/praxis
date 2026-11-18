# PRX-000019 Remote Desktop session shadowing

## Summary

Detects Windows desktop shadowing activity and policy changes that enable it. Attackers can use shadowing to observe sensitive information or control another user's session. An alert does not prove unauthorized access.

## How it works

Matches changes to the Terminal Services Shadow policy with values 1 through 4 in decimal or hexadecimal form. Separately, matches mstsc with a parsed /shadow: argument, or RdpSaUacHelper and RdpSaProxy started by svchost. Process names and original PE filenames identify the binaries, including renamed copies with preserved metadata. Matches ignore letter case. Policy values 1 and 3 require consent. Values 2 and 4 do not require consent. A policy change shows capability, not an established session.

## Blind spots and known gaps

Requires normalized Windows process or registry events. Missing parsed arguments hide mstsc activity. Renamed binaries need original PE metadata. Helper detection requires the recorded svchost parent name. Other clients and other policy paths can evade detection. Existing policies cause no registry alert until they change. The rule cannot establish authorization, successful access, or user consent.

## SOC triage

1. Identify the account, host, executable path, parent process, and matched branch.
2. Inspect the shadow session identifier and target in the command arguments.
3. Check the policy value and whether the command requests control or suppresses consent.
4. Verify the support request and target user's authorization with the host owner.
5. Correlate nearby logons, session enumeration, policy changes, and activity from the same account on other hosts.
6. Preserve the process and registry evidence before containment.
7. Escalate unexplained shadowing or policy changes that remove consent.

## Tuning history

None yet.
