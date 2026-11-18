# PRX-000022 Unexpected child process from DNS service

## Summary

Unexpected children of the Windows DNS service can indicate execution after exploitation. This detection supports investigation of remote service compromise.

## How it works

The query checks Windows process starts with a DNS parent name or original PE file name. It excludes console hosts and DNS children at standard system paths. It excludes the ReasonLabs application only through its specific parent path. Both drive paths and device paths support these exclusions. Missing executable paths do not suppress alerts. The query does not exclude all children in a vendor directory.

## Blind spots and known gaps

A match does not prove exploitation or public exposure. T1190 applies when investigation confirms a public service; T1210 applies to internal remote exploitation. The selection addresses the exploitation gap, not command interpreter coverage. Execution inside the service and indirect descendants do not match. Renamed parents need original PE metadata. Excluded paths can hide malicious activity. Missing parent identity prevents matching.

## SOC triage

1. Verify the parent path and service identity.
2. Inspect the child command line, path, signature, and original PE file name.
3. Recover the process tree and inspect descendants for payload execution.
4. Correlate DNS requests, service crashes, file changes, and network connections.
5. Check public exposure and patch status before assigning the exploitation technique.
6. Confirm crash reporting with service logs before closing the alert.
7. Preserve evidence and escalate suspected exploitation for containment.

## Tuning history

None yet.
