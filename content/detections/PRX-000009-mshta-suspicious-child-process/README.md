# PRX-000009 Suspicious child process from Mshta

## Summary

Mshta can run scripts through a trusted Windows binary. This detection identifies suspicious direct children, including interpreters, system utilities, and executables in user profiles.

## How it works

The query checks Windows process starts with Mshta as the parent. It identifies the parent by its name or original PE file name. It matches selected child names, original PE file names, or executable paths under user profiles. The paths cover drive letters and device paths. Optional fields allow matching when PE metadata or executable paths are absent. The query does not require command lines or exclude vendor HTA paths.

## Blind spots and known gaps

Renamed binaries need original PE metadata unless their paths match. Missing parent identity prevents detection. Custom profile directories and indirect descendants can escape the query. Script execution inside Mshta without a matching child does not match. A match does not prove malicious intent. Vendor HTA applications can start the same utilities.

## SOC triage

1. Inspect the child command line and the parent command line for scripts, remote sources, and encoded content.
2. Recover the process tree using the host identifier and process identifiers.
3. Verify the executable paths, original names, signatures, and hashes for both processes.
4. Check related file activity and network connections for downloads, persistence, or data transfer.
5. Confirm any claimed support activity against the exact process chain and an approved change.
6. Preserve the evidence before escalating suspicious or unresolved activity for containment.

## Tuning history

None yet.
