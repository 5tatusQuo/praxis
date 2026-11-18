# PRX-000018 Winget download source addition

## Summary

Detects attempts to add a Winget download source. An attacker can use an untrusted source to supply packages for later execution. An alert does not establish that the source was added or that a package ran.

## How it works

Examines Windows process starts. Identifies Winget through its process name or optional original PE file name to detect renamed copies. Requires adjacent source and add command tokens, in that order. Matching ignores case and permits spaces, tabs, and double quotes around either token. It also matches commands that end at add. No source allowlist applies because approved sources can change.

## Blind spots and known gaps

Requires complete command lines and normalized process events. Renamed copies need original PE metadata. Unusual quoting, other whitespace, or alternate interfaces can evade detection. Text inside another argument can match the command pattern. Direct configuration changes do not match. The event does not confirm source registration, package installation, or malicious intent.

## SOC triage

1. Inspect the command, executable path, user, and parent process.
2. Identify the source address and confirm approval with the software owner.
3. Check the source configuration to confirm whether registration succeeded.
4. Review subsequent package installations and child processes for untrusted execution.
5. Escalate unexplained additions and preserve evidence before removing the source.

## Tuning history

None yet.
