# PRX-000006 Potential PowerShell reverse shell via TCP stream

## Summary

Detects Windows PowerShell or PowerShell Core starting with an inline command that mentions a .NET TCP client, obtains a stream and writes to a stream. Attackers use this pattern in reverse shells to exchange commands and output with a remote operator. This is evidence of suspicious command text, not proof that a connection succeeded or that a shell executed. Derived from Sigma rule edc2f8ae-2412-4dfd-b9d5-0c57727e70be by FPT.EagleEye, wagga and Nasreddine Bencherchali (Nextron Systems), under DRL-1.1.

## How it works

Looks at Windows process-start events from Elastic Defend or ECS-normalized Sysmon event ID 1. The process must be powershell.exe or pwsh.exe by name, or have original PE file name PowerShell.EXE or pwsh.dll so renamed copies can match. The PE field is optional. Case-insensitive command-line matching requires all three substrings: Net.Sockets.TCPClient, .GetStream( and .Write(. These need not appear in any particular order and are not required to reference the same object. Unlike the upstream mechanical translation, no leading space before Net.Sockets.TCPClient is required, covering System.Net.Sockets.TCPClient and bracket-based construction. No destination or parent restrictions are imposed. Acme's 30-day backtest returned zero hits; the deterministic quality score was 94/100. These results are not a guarantee of future alert volume.

## Blind spots and known gaps

Requires complete process command lines and ECS process-start mapping. Encoded commands, downloaded or on-disk scripts whose bodies are not present in the command line, in-process PowerShell hosts, and other languages are not covered. String concatenation, backticks, reflective calls, whitespace between a method name and its opening parenthesis, and alternate socket APIs can evade the literal matches. Renamed binaries require original PE metadata; if it is missing and the name is changed, they will be missed. The query does not prove the strings executed, share the same object, or represent a reverse shell: comments, inert strings and legitimate network scripts can match. Script-block logging and network telemetry are complementary coverage.

## SOC triage

1. Inspect the complete command line and recover the script, preserving any encoded or downloaded payload. Identify the TCP destination, port and whether incoming data is executed and output returned.
2. Check the process tree, user, executable path, signer and original PE name. Investigate renamed PowerShell, unexpected service accounts, Office/browser parents or remote-execution ancestry.
3. Correlate network connections for this process and time with DNS, firewall and endpoint events. Determine whether the destination was reached; review child processes and subsequent file or credential activity.
4. Check whether this is an approved diagnostic script or authorized security test with the responsible owner. Do not suppress all PowerShell or all internal destinations; scope any tuning to a verified script and execution context.
5. If malicious activity is confirmed, isolate the host and block the destination per incident procedure, preserve process/script evidence, and scope affected accounts and related hosts.

## Tuning history

None yet.
