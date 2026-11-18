# PRX-000004 Service registry deletion via reg.exe

## Summary

Detects Windows reg.exe attempts to delete service registry keys or values. Removing service configuration can prevent endpoint protection or other defenses from starting. This is an attempted operation, not proof that the deletion succeeded or that the targeted service is a security product. Derived from Sigma's Service Registry Key Deleted Via Reg.EXE by Nasreddine Bencherchali (Nextron Systems), under DRL-1.1; source and pinned revision are in References.

## How it works

Examines Windows process-start events from Elastic Defend or ECS-normalized Sysmon event ID 1. Identifies reg.exe by case-insensitive process name or optional original PE file name, including renamed copies. Requires the delete argument, either in optional parsed process.args or common space/tab-delimited command-line forms (including quoted delete). The command line must contain the Services tree under CurrentControlSet or a three-character numbered-control-set-shaped ControlSet suffix. Matches service subkeys and the Services root, including quoted roots and roots followed by switches; value deletion also matches. No service-name allowlist is used because attackers can target any installed defense. Library review found no existing equivalent. Deterministic quality score was 94/100; acme's 30-day backtest returned zero hits. This does not establish detection efficacy on unobserved attacks.

## Blind spots and known gaps

Needs full command lines and normalized Windows process-start telemetry. Does not observe direct registry API calls, PowerShell registry cmdlets, reg import operations, service deletion via sc.exe, or changes made without reg.exe. Renamed binaries require original PE metadata; without it a renamed reg.exe is missed. Without parsed arguments, unusual quoting or whitespace beyond the listed forms can evade the delete check. Path matching is textual, not registry resolution: aliases, alternate paths and variable expansion may evade it, and a path mentioned in another argument may match. ControlSet??? matches any three characters, not only digits. Deletes below Services may remove ordinary configuration rather than disable a service. No exit status, successful registry deletion, security-product identity, or malicious intent is established.

## SOC triage

1. Inspect the complete command, host, user, parent process and executable path. Determine the actual registry target and whether /v, /ve or /va limits deletion to values; confirm whether the command succeeded with registry telemetry or host evidence.
2. Resolve the service name to its executable and vendor. Prioritize endpoint protection, logging and other security services; check service state, configuration and associated alerts.
3. Verify a change ticket or software removal/upgrade with the responsible owner. Do not assume a signed reg.exe or SYSTEM account makes the activity benign.
4. Review neighboring process, registry and service events for remote execution, defense tampering and follow-on impact. Search the same command and account across hosts.
5. Escalate unexplained security-service tampering and contain according to the incident playbook. Preserve the command, process ancestry and registry evidence before authorized restoration.

## Tuning history

None yet.
