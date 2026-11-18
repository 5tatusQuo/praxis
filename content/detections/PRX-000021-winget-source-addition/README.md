# PRX-000021 Winget source addition

## Summary

Detects attempts to add a Winget source. An attacker can use an untrusted source to distribute packages. The event does not prove successful registration or installation.

## How it works

Examines Windows process start events. Identifies Winget by its process name or optional original PE file name. Matches adjacent source and add commands without case sensitivity. Covers common spaces, tabs, and quoted command forms. Requires command boundaries to avoid matching unrelated argument fragments. Does not exclude approved sources because their approval depends on local policy.

## Blind spots and known gaps

Requires complete command lines and normalized process events. Renamed copies need original PE metadata. Unlisted whitespace and quoting forms can evade matching. Options between source and add do not match. Text inside another argument can match. The rule does not confirm success, source trust, package execution, or use of a command interpreter.

## SOC triage

1. Inspect the command, executable path, user, and parent process.
2. Identify the source address and check its ownership.
3. Verify the change with the responsible administrator.
4. Check Winget logs and source configuration for successful registration.
5. Review later package installations and child processes.
6. Escalate unapproved changes under the incident procedure.

## Tuning history

None yet.
