# PRX-000025 Command line path traversal evasion

## Summary

Detects unusual parent directory references in Windows command lines. Attackers can use these references to hide executable paths from rules that match literal paths.

## How it works

The query checks process starts without requiring a binary name. It matches a Windows executable with traversal toward Windows or System32, or two consecutive parent directory references. It also matches a command line containing an executable suffix followed by a parent directory reference, regardless of the executable location. Matching ignores letter case. The query excludes two known application patterns only when the executable path also matches the application. Optional fields allow the executable suffix condition to work without an executable path.

## Blind spots and known gaps

Missing command lines prevent detection. Other traversal forms, forward separators, and paths normalized before collection do not match. Matches can occur in arguments, not only executable paths. The application exclusions use paths, not verified signatures. An attacker who controls those paths can evade detection. This rule does not prove that Windows resolved or executed a referenced path.

## SOC triage

1. Read the complete command line and identify each parent directory reference.
2. Resolve the referenced path and compare it with the recorded executable path.
3. Check the parent process, user, file signature, and file hash.
4. Review nearby process starts for payload execution or unusual child processes.
5. Confirm application ownership before adding a narrow exception.
6. Escalate unexplained execution that uses traversal to hide a payload.

## Tuning history

None yet.
