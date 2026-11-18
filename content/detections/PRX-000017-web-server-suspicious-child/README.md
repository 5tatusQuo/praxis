# PRX-000017 Suspicious utility started by a web server

## Summary

This detection identifies web servers that start shells or selected system utilities. These processes can indicate exploitation or commands from a web shell.

## How it works

The query checks Windows process starts with a known web server as the direct parent. It identifies the parent and child by their names or original PE file names. Java parents also require Tomcat indicators in the executable path or command line. The child must be a selected shell or system utility. Optional fields allow matching without PE metadata, executable paths, or command lines. The query omits vendor exclusions because command strings alone do not establish authorized activity.

## Blind spots and known gaps

The query does not detect exploitation itself or prove that a web shell exists. It misses indirect descendants, unlisted utilities, and commands executed inside the server. Renamed processes need matching original PE metadata. Missing parent identity prevents detection. Java needs Tomcat indicators. Other operating systems do not match. Legitimate web applications can start the same utilities.

## SOC triage

1. Inspect the parent and child command lines for scripts, encoded commands, downloads, and discovery activity.
2. Recover the process tree with the host identifier and process identifiers.
3. Check executable paths, original names, signatures, and the service account.
4. Correlate the process start with web requests, application errors, and recently changed server files.
5. Verify the exact activity with the application owner and an approved change.
6. Preserve relevant files and logs before escalating unexplained activity for containment.

## Tuning history

None yet.
