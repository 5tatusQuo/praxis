# PRX-000022 Unexpected child of the Windows DNS service

## Summary

Unexpected children of the Windows DNS service can indicate remote exploitation. The detection identifies these process starts for investigation.

## How it works

The query checks Windows process starts with a DNS parent name or original PE file name. It excludes conhost.exe and dns.exe children only at specified Windows system paths. It excludes the ReasonLabs DNS application at its specific parent path. Both drive paths and device paths are supported. Missing executable paths do not suppress a match. The query does not exclude an entire vendor directory for children.

## Blind spots and known gaps

A match does not prove exploitation or public exposure. Renamed parents need original PE metadata. Missing parent identity prevents matching. Execution inside the service and indirect descendants do not match. The excluded paths can hide replaced binaries. The ReasonLabs parent exclusion can hide abuse at that path. Crash reporting can match after a legitimate fault or a denial of service attempt.

## SOC triage

1. Inspect the child command line, executable path, signature, and original PE file name.
2. Confirm the parent belongs to the Windows DNS service.
3. Recover the process tree using host and process identifiers.
4. Check service errors and crash reports for the same time.
5. Correlate network connections, file changes, and descendant processes.
6. Verify public exposure and the patch status for CVE-2020-1350.
7. Preserve evidence before escalating suspected exploitation for containment.

## Tuning history

None yet.
