# PRX-000021 Winget download source added

## Summary

Detects attempts to add a package source through Winget. An attacker can use a new source to prepare malicious package downloads.

## How it works

The query checks Windows process starts. It identifies Winget by its process name or original PE file name, including renamed copies. It requires consecutive source and add command tokens. Matching ignores case and permits quoted tokens, spaces, and tabs. Separate token boundaries prevent matches on source names that contain these words.

## Blind spots and known gaps

A process start does not prove that the source was added or that a package was transferred. Missing command lines prevent detection. Direct changes to source configuration and other download tools do not match. This selection supports transfer coverage only. Treat it as supporting coverage, not as closure of the command interpreter gap.

## SOC triage

1. Check the source address and compare it with approved package sources.
2. Check the user and parent process for an authorized deployment.
3. Inspect subsequent package installations and network connections on the host.
4. Investigate downloaded packages and their child processes if the source is unapproved.

## Tuning history

None yet.
