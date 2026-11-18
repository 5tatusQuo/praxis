# PRX-000029 Certutil used to download a file from a URL

## Summary

Fires when certutil.exe starts with a download option and a URL. Ransomware crews use this built-in tool to bring payloads onto a host.

## How it works

The query looks at Windows process starts. It matches certutil.exe by name or by original PE file name, so a renamed copy still matches. The command line must contain urlcache or verifyctl, and a URL.

## Blind spots and known gaps

- Other download tools (bitsadmin, curl, PowerShell) need their own rules.
- Hosts that do not log command lines are invisible to this rule.
- A renamed copy on a host without PE metadata is missed.

## SOC triage

1. Read the URL in the command line and check its reputation.
2. Find the file that was written and check its hash.
3. Check the parent process and the user.
4. Look for the downloaded file being executed afterwards.

## Tuning history

None yet.
