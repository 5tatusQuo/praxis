# PRX-000021 Winget package source addition

## Summary

Detects attempts to add a Winget package source. An attacker can configure an untrusted source before retrieving malicious packages.

## How it works

The query checks Windows process starts for Winget. The optional original PE file name identifies renamed copies. The command must place source and add directly after the executable token. Matching ignores letter case and accepts quoted tokens, spaces, and tabs. Unrelated arguments containing these words do not match. The transfer mapping describes preparation, not a confirmed transfer. This candidate does not close the command interpreter coverage gap.

## Blind spots and known gaps

The query does not confirm a source change, package retrieval, or malicious intent. Help requests and failed commands can match. Missing command lines prevent detection. Renamed copies need the original PE file name. Direct configuration changes and other package tools need separate detections. Approved source additions can match.

## SOC triage

1. Identify the account, host, and parent process.
2. Extract the source name and address from the command.
3. Confirm the source owner and change approval.
4. Check nearby Winget commands and network events for package retrieval.
5. Inspect retrieved packages and subsequent processes for malicious activity.
6. Escalate unapproved sources with related retrieval or execution evidence.

## Tuning history

None yet.
