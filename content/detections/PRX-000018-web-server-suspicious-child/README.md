# PRX-000018 Suspicious child process from a web server

## Summary

A web server that starts an interpreter or system utility can indicate exploitation or a web shell. This detection identifies these direct children.

## How it works

The query checks Windows process starts. It identifies web servers by their process names or original PE file names. Java parents also need a Tomcat path or a Catalina marker in their command lines. The child must match a selected interpreter or system utility by name or original PE file name. Optional fields allow matching without PE metadata or command lines. The query does not exclude vendor commands.

## Blind spots and known gaps

Missing parent identity prevents detection. Renamed binaries need original PE metadata. Java parents need Tomcat context. Indirect descendants and execution inside the server do not match. Unlisted utilities and non-Windows servers do not match. A match does not prove exploitation or a web shell.

## SOC triage

1. Inspect the parent and child command lines for scripts, encoded commands, and remote sources.
2. Recover the process tree using the host identifier and process identifiers.
3. Check the web logs for related requests and signs of exploitation.
4. Inspect recent file changes in web directories for scripts and uploaded executables.
5. Verify the executable paths, signatures, and original names.
6. Confirm maintenance activity with the application owner before adding an exception.
7. Preserve evidence and escalate suspicious activity for containment.

## Tuning history

None yet.
