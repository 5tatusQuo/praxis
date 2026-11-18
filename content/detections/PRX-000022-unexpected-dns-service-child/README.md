# PRX-000022 Unexpected child of the Windows DNS service

## Summary

Unexpected children of the Windows DNS service can indicate remote code execution. This detection identifies direct children that need investigation.

## How it works

The query checks Windows process starts with a DNS parent name or original PE file name. This also identifies renamed parents when metadata exists. It excludes conhost.exe and dns.exe only at standard System32 paths, including device paths. It excludes the specific ReasonLabs DNS parent path, not all children in the vendor directory. Missing optional paths do not prevent a match. Crash reporters remain in scope because a crash can follow an exploitation attempt.

## Blind spots and known gaps

A match does not prove exploitation or public exposure. Execution inside the service and indirect descendants do not match. Renamed parents need original PE metadata. Excluded paths can conceal replaced binaries. Missing parent identity prevents matching. The ReasonLabs parent exception can conceal abuse at that path.

## SOC triage

1. Inspect the child command line and the parent path.
2. Recover the process tree with host and process identifiers.
3. Check the child signature, hash, and original PE file name.
4. Correlate the start with DNS requests, service crashes, file changes, and network connections.
5. Confirm crash reporting with service errors and the absence of suspicious descendants.
6. Check service exposure and the patch status for CVE-2020-1350.
7. Preserve evidence before escalating suspected exploitation for containment.

## Tuning history

None yet.
