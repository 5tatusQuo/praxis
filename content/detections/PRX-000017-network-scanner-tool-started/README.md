# PRX-000017 Network scanning tool started on a Windows host

## Summary

Fires when a well-known network or port scanner starts on a Windows host. Ransomware operators run these tools to find servers and open services before they move laterally.

## How it works

The query looks at Windows process starts. It matches a short list of scanner tools by process name. It also matches the original PE file name, so a renamed copy still matches. The list covers Advanced IP Scanner, Advanced Port Scanner, SoftPerfect Network Scanner, Nmap, Masscan and Angry IP Scanner.

## Blind spots and known gaps

- Scanners that are not on the list are not seen.
- Scanning with built-in tools or PowerShell loops starts no listed process.
- A renamed tool with a stripped PE header does not match.
- Scans from a device without an endpoint agent are invisible to this rule.

## SOC triage

1. Identify the user and the host, and check whether IT ran the scan.
2. Check the folder the tool ran from, such as Downloads or a temp folder.
3. Look for remote logons or new services on other hosts soon after.
4. If nobody owns the scan, isolate the host and escalate.

## Tuning history

None yet.
