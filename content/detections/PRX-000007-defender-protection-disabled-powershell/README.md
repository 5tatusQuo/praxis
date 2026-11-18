# PRX-000007 Microsoft Defender protection disabled with PowerShell

## Summary

Fires when PowerShell runs Set-MpPreference with an option that turns a Defender protection feature off. Ransomware crews do this before encryption.

## How it works

The query looks at Windows process starts. It matches PowerShell by name or by original PE file name, so a renamed copy still matches. The command line must contain Set-MpPreference, one of four Disable options, and a true value.

## Blind spots and known gaps

- Defender disabled through the registry, Group Policy or a vulnerable driver needs its own rule.
- Encoded PowerShell command lines hide the option names from this rule.
- Exclusions added with Add-MpPreference are not covered.

## SOC triage

1. Read the command line and note which protection feature was turned off.
2. Check the parent process and the user account.
3. Look for new tools or remote logons on the host in the hour before.
4. If unexplained, isolate the host and turn the protection back on.

## Tuning history

None yet.
