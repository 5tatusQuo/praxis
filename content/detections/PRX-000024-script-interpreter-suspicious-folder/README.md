# PRX-000024 Script interpreter references a suspicious folder

## Summary

Script interpreters can execute attacker-controlled files from writable folders. This detection identifies interpreter commands that reference temporary folders, public folders, startup folders, or selected user folders.

## How it works

The query checks Windows process starts. It identifies script hosts by their names or original PE file names. It also identifies PowerShell, including PowerShell Core, with policy bypass or hidden window options. The command line must reference a selected folder or environment variable. Matching ignores letter case. Optional fields tolerate absent metadata. Folder separators prevent matches on similar folder names. The query does not prove that the interpreter executes the referenced file.

## Blind spots and known gaps

Missing command lines prevent detection. Renamed interpreters need original PE metadata. Other interpreters, custom folders, relative paths, alternate path formats, and unlisted option abbreviations can escape detection. PowerShell without the selected options does not match. A folder reference can describe an output file or quoted text instead of an executed script.

## SOC triage

1. Inspect the command line to identify the script and the referenced folder.
2. Retrieve the script safely and inspect its contents without execution.
3. Check the parent process, user account, executable signature, and original file name.
4. Review related file activity and network connections for downloads and persistence.
5. Confirm installation or maintenance activity against an approved change.
6. Preserve the evidence and escalate unexplained script execution for containment.

## Tuning history

None yet.
