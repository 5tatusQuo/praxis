# PRX-000015 7-Zip archives dump files

## Summary

Detects a dump file argument during archive creation or updates. Attackers can archive memory dumps before data theft.

## How it works

The query checks Windows process starts. It identifies the archiver through its name, original PE name, or description. Original PE names can identify renamed copies. The command line or argument list must contain an add or update command. The command line must contain a dump extension before its end, a space, or a quotation mark.

## Blind spots and known gaps

The rule does not confirm archive creation or distinguish source files from archive names. It misses dump files selected through folders or list files. Other archivers and graphical operations do not match. Missing command lines prevent detection. Without argument lists, unusual spacing can prevent detection. Metadata changes can hide renamed tools.

## SOC triage

1. Read the command line to identify the archive and dump paths.
2. Check the user and parent process for an approved support task.
3. Check how the dump was created and which process it contains.
4. Look for archive transfers from the host.
5. Escalate unapproved activity involving sensitive dumps.

## Tuning history

None yet.
