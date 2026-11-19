# PRX-000033 Winget installation from a local manifest

## Summary

Detects installation attempts that use a local manifest. Attackers can use a manifest to select a remote installer and run a payload.

## How it works

The query checks Windows process starts. It identifies the executable by its name or original PE file name to detect renamed copies. It requires the install or add command and a manifest option. Argument matching accepts the short option, long option, and long option with an equals sign. When arguments are absent, the query checks the command line for space-delimited commands and options.

## Blind spots and known gaps

The event shows an attempt, not a successful installation or malicious manifest. Missing arguments and command lines prevent detection. Without arguments, unusual spacing or quoted command tokens can evade matching. A renamed executable needs its original PE file name. Other installation methods need separate detections.

## SOC triage

1. Check the user and parent process for an approved installation task.
2. Retrieve the manifest from the recorded path without running its installer.
3. Inspect the installer address and hash in the manifest.
4. Check subsequent child processes and downloads for payload execution.
5. Escalate unapproved activity with the manifest and process evidence.

## Tuning history

None yet.
