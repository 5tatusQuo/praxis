# PRX-000011 Password-protected archive created with a command-line archiver

## Summary

Fires when rar.exe, WinRAR or 7-Zip starts with the add command and a password option. Attackers encrypt archives of collected files before they move them out.

## How it works

The query looks at Windows process starts. It matches WinRAR and 7-Zip by process name or by original PE file name, so a renamed copy still matches. The command line must contain the add command and a password switch.

## Blind spots and known gaps

- Archives made in the graphical interface carry no command line switches.
- Other tools, such as tar, makecab or PowerShell Compress-Archive, need their own rules.
- Hosts that do not log command lines are invisible to this rule.

## SOC triage

1. Read the command line to find the archive name and the source folders.
2. Check the parent process and the user who ran it.
3. Look for the archive leaving the host by upload, copy or remote share.
4. Ask the user whether they made the archive.

## Tuning history

None yet.
