# PRX-000018 Suspicious utility started by a web server

## Summary

Web servers that start shells or system utilities can expose command execution after exploitation. This detection identifies suspicious direct children for investigation.

## How it works

The query checks Windows process starts. It identifies web servers by their process names or original PE file names. Java parents also need a Tomcat path or a Catalina marker in their command line. Selected child names identify shells, script interpreters, and system utilities. Original PE file names also identify renamed children. Optional fields allow matching without PE metadata or command lines. The query does not apply the upstream product exceptions because command strings alone do not establish authorized activity.

## Blind spots and known gaps

A match does not prove exploitation or a web shell. Legitimate applications can start the same utilities. Renamed processes need original PE metadata. Missing parent identity prevents matching. Indirect descendants, unlisted utilities, and execution inside the server process do not match. The query does not cover other operating systems or prove the initial access method.

## SOC triage

1. Inspect the child command line and parent command line for scripts, encoded commands, and remote addresses.
2. Recover the process tree using host and process identifiers.
3. Check executable paths, signatures, and original PE file names.
4. Correlate the process start with web requests, application errors, file changes, and network connections.
5. Confirm the activity with the application owner and an approved change.
6. Preserve the evidence before escalating suspected exploitation for containment.

## Tuning history

None yet.
