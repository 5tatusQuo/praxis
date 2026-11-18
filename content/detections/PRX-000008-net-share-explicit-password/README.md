# PRX-000008 Explicit password in net share connection

## Summary

Detects net connections to shared folders with an explicit account and a password in the command line. This behavior can indicate account misuse and exposes credentials to process logging.

## How it works

The query checks Windows process starts for net.exe or net1.exe. The original PE file name also identifies renamed copies. The command must contain use, a UNC destination, an explicit user option, and a password token. A drive letter is optional. The password can precede or follow the user option. Matching ignores letter case and accepts spaces or tabs between tokens. The query excludes password prompts and options without a password. It requires complete command lines from Elastic Defend or Sysmon process events.

## Blind spots and known gaps

The query does not confirm successful authentication or malicious intent. Missing command lines prevent detection. Connections without an explicit user option do not match. Unusual option order can prevent matching. Passwords that start with an asterisk or a forward slash do not match. Other tools and direct API calls need separate detections.

## SOC triage

1. Restrict access to the event because the command line contains a password.
2. Identify the account and destination without copying the password into a ticket.
3. Check the parent process and script owner for approved automation.
4. Check destination authentication records and subsequent file access for successful use.
5. Escalate unapproved activity for containment and credential rotation.

## Tuning history

None yet.
