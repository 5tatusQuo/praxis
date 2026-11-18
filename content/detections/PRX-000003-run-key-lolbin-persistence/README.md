# PRX-000003 Run key set to a script host or a world-writable path

## Summary

Fires when a `Run` or `RunOnce` registry value is created or changed so that it
starts a script host, another living-off-the-land binary, or a program stored
in a folder any user can write to. Attackers use these values to survive a
reboot or logoff.

## How it works

The query looks at Windows registry events of type creation or change under
the per-user and per-machine `CurrentVersion\Run` and `RunOnce` keys, including
the 32-bit `WOW6432Node` view. It then inspects the data written to the value
and matches when it mentions:

- a script host or proxy binary: PowerShell, `wscript`, `cscript`, `mshta`,
  `rundll32` or `regsvr32`;
- or a path under `Users\Public`, `ProgramData`, `Windows\Temp` or the user's
  `AppData\Local\Temp`.

Ordinary software that registers a program from `Program Files` or from
`AppData\Local\<vendor>` does not match. It needs registry events from Elastic
Defend.

## Blind spots and known gaps

- Malware installed under `AppData\Roaming` or `AppData\Local\<name>` with an
  ordinary executable is not matched; that pattern is too common in legitimate
  software to alert on without more context.
- Other autostart locations (services, scheduled tasks, startup folder,
  `Winlogon`, `Image File Execution Options`) need their own detections.
- Elastic Defend reports a curated set of registry paths. Hosts without the
  registry event collection enabled are invisible to this rule.

## SOC triage

1. Read the value data: what will run at logon, and from where? A script host
   with an encoded or remote argument, or a binary in a temp folder, is bad.
2. Identify the process that wrote the value and its parent. An installer run
   by a deployment tool is expected; an Office application, a browser or a
   script host writing a Run value is not.
3. Check the file the value points at: when was it created, by which process,
   is it signed, and is it present on other hosts?
4. If malicious: remove the value and the file, then look for how the writing
   process got onto the host.

## Tuning history

None yet.
