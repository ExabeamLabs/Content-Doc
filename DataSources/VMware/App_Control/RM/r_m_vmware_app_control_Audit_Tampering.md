Vendor: VMware
==============
### Product: [App Control](../ds_vmware_app_control.md)
### Use-Case: [Audit Tampering](../../../../UseCases/uc_audit_tampering.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   0    |     6      |     15      |   15    |

| Event Type      | Rules    | Models |
| ---- | ---- | ------ |
| process-created | <b>T1562.006 - T1562.006</b><br> ↳ <b>A-ETW-Trace-Disable</b>: Event tracing has been disabled, possible logging evasion on this asset<br> ↳ <b>ETW-Trace-Disable</b>: Event tracing has been disabled, possible logging evasion<br> ↳ <b>Sysmon-Driver-Unload</b>: Possible Sysmon driver unloaded.<br><br><b>T1059 - Command and Scripting Interperter</b><br> ↳ <b>A-ETW-Trace-Disable</b>: Event tracing has been disabled, possible logging evasion on this asset<br> ↳ <b>ETW-Trace-Disable</b>: Event tracing has been disabled, possible logging evasion<br><br><b>T1070 - Indicator Removal on Host</b><br> ↳ <b>A-ETW-Trace-Disable</b>: Event tracing has been disabled, possible logging evasion on this asset<br> ↳ <b>ETW-Trace-Disable</b>: Event tracing has been disabled, possible logging evasion<br><br><b>T1070.001 - Indicator Removal on Host: Clear Windows Event Logs</b><br> ↳ <b>A-EventLog-Tamper</b>: EventLog has been tampered with on this asset<br> ↳ <b>EventLog-Tamper</b>: EventLog has been tampered with<br><br><b>T1546.003 - T1546.003</b><br> ↳ <b>A-WMI-Script-Event-Consumers</b>: Suspicious usage of WMI script event consumers on this asset.<br><br><b>T1562 - Impair Defenses</b><br> ↳ <b>A-Sysmon-Driver-Unload</b>: Possible Sysmon driver unloaded on this asset. |        |