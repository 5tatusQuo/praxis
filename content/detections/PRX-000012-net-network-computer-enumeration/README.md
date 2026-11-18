# PRX-000012 Network computer enumeration with net

## Summary

Detects net view commands that enumerate computers without a UNC target. Attackers can use this discovery step to select remote systems.

## How it works

The query checks Windows process starts for net.exe or net1.exe. The optional original PE file name identifies renamed copies. The command must place view directly after the executable token. Matching ignores letter case and accepts quoted tokens, spaces, and tabs. Commands with a UNC path do not match. This keeps the focus on computer enumeration rather than share enumeration on a specific server. The password connection detection matches a different subcommand and does not cover this behavior.

## Blind spots and known gaps

The query does not confirm successful enumeration or malicious intent. Missing command lines prevent detection. Renamed copies need the original PE file name. Commands with UNC paths do not match. Other tools and direct API calls need separate detections. Approved administrators can run the same commands.

## SOC triage

1. Identify the account and parent process.
2. Confirm whether the administrator approved the discovery task.
3. Check nearby process events for domain discovery and remote connection commands.
4. Check authentication events on remote systems for subsequent access.
5. Escalate unapproved discovery with related access evidence.

## Tuning history

None yet.
