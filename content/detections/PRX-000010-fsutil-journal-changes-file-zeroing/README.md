# PRX-000010 Fsutil journal changes or file zeroing

## Summary

Detects journal deletion, journal creation, or file zeroing through fsutil. These operations can remove forensic evidence or destroy data.

## How it works

The query selects Windows process starts. It identifies fsutil by its process name or original PE file name, which also detects renamed copies. It matches usn with deletejournal or createjournal, and file with setzerodata, without case sensitivity. Journal creation can resize an existing journal. The query does not assess the requested size or confirm that the operation succeeds.

## Blind spots and known gaps

Direct API calls and other tools do not match. Missing command lines prevent detection. Renamed copies require the original PE file name. The query detects all journal creation requests, including routine maintenance. Wildcard matching does not validate argument boundaries. An alert indicates an invocation, not confirmed evidence removal or data loss.

## SOC triage

1. Check the user, parent process, command line, and target volume or file.
2. Confirm whether an approved maintenance task explains the operation.
3. Inspect journal size arguments and the target file for evidence of destructive intent.
4. Check nearby events for remote execution, encryption, and other attempts to remove evidence.
5. Escalate unexplained destructive activity through the incident response process.

## Tuning history

None yet.
