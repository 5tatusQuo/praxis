# PRX-000022 Unexpected child of the DNS service

## Summary

Unexpected children of the Windows DNS service can indicate execution after exploitation. This detection identifies direct children that need investigation.

## How it works

The query checks Windows process starts. It identifies the parent by its name or original PE file name to include renamed copies. It excludes conhost.exe and dns.exe only at standard Windows system paths, including device paths. It excludes the specific ReasonLabs parent path, not the entire vendor directory. Missing executable paths do not suppress detection. Matching ignores case.

## Blind spots and known gaps

A match does not prove exploitation, public exposure, or a file transfer. The mapping describes possible exploitation, not confirmed initial access. Execution inside the service and indirect descendants do not match. Renamed parents need original PE metadata. Excluded paths can hide replaced binaries. Missing parent identity prevents detection. This detection does not close command interpreter or transfer gaps. The separate Winget selection supports T1105 only and does not replace exploitation coverage.

## SOC triage

1. Inspect the child command line, executable path, signature, and original PE file name.
2. Confirm that the parent belongs to the Windows DNS service.
3. Check service errors and crash reports before treating WerFault.exe as benign.
4. Recover descendants, file changes, and network connections using the host and process identifiers.
5. Check DNS exposure, patch status, and related requests for evidence of exploitation.
6. Preserve evidence before escalating suspicious execution for containment.

## Tuning history

None yet.
