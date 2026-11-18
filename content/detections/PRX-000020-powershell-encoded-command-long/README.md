# PRX-000020 PowerShell started with a long encoded command

## Summary

Fires when PowerShell starts with an encoded command of 100 or more Base64 characters. Attackers encode commands so the real script is not readable in process logs.

## How it works

The query looks at Windows process starts. It matches powershell.exe and pwsh.exe by name or by original PE file name, so a renamed copy still matches. The command line must hold an encoded-command option, in any abbreviation PowerShell accepts. The option must be followed by at least 100 Base64 characters. Short encoded commands are ignored to keep noise down.

## Blind spots and known gaps

- Encoded commands shorter than 100 characters are not seen.
- Scripts decoded inside PowerShell, with FromBase64String, start no encoded process.
- Other obfuscation, such as string concatenation or carets, needs its own rule.
- Hosts that do not log command lines are invisible to this rule.

## SOC triage

1. Decode the Base64 text as UTF-16LE and read the script.
2. Check the parent process and the user who started it.
3. Look for downloads, new processes or network connections from the same host.
4. If the script is from a known management agent, propose a tuning for it.

## Tuning history

None yet.
