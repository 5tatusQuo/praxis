# PRX-000027 Renamed CreateDump utility execution

## Summary

Detects CreateDump starting under a different file name on Windows. Attackers can rename this utility to hide memory collection, including possible credential theft.

## How it works

The query checks process starts for either CreateDump original file name in the PE metadata. It requires an executable path that does not end with createdump.exe. The comparisons ignore letter case. It does not require dump arguments because attackers can change them. Generic dump arguments alone do not identify CreateDump. An alert shows renamed execution, not a successful dump or confirmed access to LSASS.

## Blind spots and known gaps

Missing or changed PE metadata prevents a match. Missing executable paths also prevent a match. Execution under the normal file name is outside this rule. The rule does not identify the target process or confirm that a dump file exists.

## SOC triage

1. Check the executable path, signature, and PE metadata to confirm the utility identity.
2. Review the parent process, user, and command line for approved diagnostic work.
3. Identify the target process from the arguments and related process access events.
4. Search for dump files and later archive creation or network transfers.
5. Escalate unapproved memory collection, especially when the target is LSASS.

## Tuning history

None yet.
