# PRX-000023 Bitsadmin used to download a file from a URL

## Summary

Fires when bitsadmin.exe starts with a transfer option and a URL. Attackers use this built-in tool to bring files onto a host.

## How it works

The query looks at Windows process starts. It matches bitsadmin.exe by name or by original PE file name, so a renamed copy still matches. The command line must contain transfer or addfile, and a web or FTP address.

## Blind spots and known gaps

- BITS jobs created with PowerShell (Start-BitsTransfer) start no bitsadmin process.
- Other download tools (certutil, curl, PowerShell) need their own rules.
- Hosts that do not log command lines are invisible to this rule.

## SOC triage

1. Read the URL in the command line and check its reputation.
2. Find the file that was written and check its hash.
3. Check the parent process and the user.
4. Look for the downloaded file being run soon afterwards.

## Tuning history

None yet.
