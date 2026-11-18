# PRX-000005 RDP registry configuration modified via reg.exe

## Summary

Detects Windows reg.exe attempts to change RDP-related Terminal Server registry configuration. Attackers can enable remote access, adjust session restrictions or weaken listener security before lateral movement. An alert establishes an attempted command, not successful modification or an RDP session. Derived from Sigma's Potential Tampering With RDP Related Registry Keys Via Reg.EXE by pH-T (Nextron Systems), @Kostastsale and TheDFIRReport, under DRL-1.1; the pinned upstream source is in References.

## How it works

Examines Windows process-start events from Elastic Defend or ECS-normalized Sysmon. Matches reg.exe by case-insensitive process name or optional original PE filename so renamed copies remain detectable. Requires add in optional parsed arguments or common space/tab-delimited command-line forms. Requires the SYSTEM Terminal Server tree under CurrentControlSet or a numbered-control-set-shaped ControlSet??? path, plus one of the selected connection, session, licensing or security value names, or the RDP-Tcp listener subkey. Matching is case insensitive. Does not require REG_DWORD or /f: these are not necessary for an attempted change. Unlike the upstream rule, does not suppress commands containing SecurityLayer and the arbitrary substring 02; legitimate TLS hardening can therefore alert and must be triaged. Values and data are not parsed semantically, so both enabling and disabling changes can match. Library review found no equivalent; quality score was 94/100 and the exact query returned zero hits over acme's last 30 days. This is not proof of efficacy on unobserved attacks.

## Blind spots and known gaps

Requires full command lines and ECS-normalized Windows process-start telemetry. Does not detect PowerShell registry cmdlets, direct registry APIs, reg import, registry deletion, policy-based paths or other tools. Renamed reg.exe requires original PE metadata. Unusual argument quoting/whitespace may evade fallback matching when parsed arguments are unavailable. ControlSet??? accepts any three characters, not only digits. Registry paths and value names are textual matches anywhere in the command, not resolved registry targets; strings inside unrelated data can match. Variables, aliases and alternate paths may evade matching. The rule does not determine data direction, previous value, command success, malicious intent, listener reachability or actual lateral movement. Authorized hardening, including SecurityLayer=2, can alert.

## SOC triage

1. Inspect host, account, full command line, executable path and parent process. Identify the actual registry key, value and /d data; confirm success and the before/after state using registry telemetry or host evidence.
2. Determine impact: fDenyTSConnections=0 permits RDP; inspect SecurityLayer, listener authentication, session limits and firewall configuration. Do not assume every matched change weakens security.
3. Verify an approved provisioning or maintenance ticket with the host owner. Signed reg.exe and SYSTEM execution alone do not establish legitimacy.
4. Correlate nearby remote logons (including Windows logon type 10), source addresses, remote execution, new accounts, firewall changes and credential-access alerts. Search the account and command across hosts.
5. Escalate unexplained enablement or security weakening under the incident playbook; preserve process and registry evidence before authorized containment or configuration restoration.

## Tuning history

None yet.
