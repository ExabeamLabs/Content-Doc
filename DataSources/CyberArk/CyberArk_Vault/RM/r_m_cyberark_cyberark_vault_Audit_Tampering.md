Vendor: CyberArk
================
### Product: [CyberArk Vault](../ds_cyberark_cyberark_vault.md)
### Use-Case: [Audit Tampering](../../../../UseCases/uc_audit_tampering.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   0    |     2      |     15      |   15    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Models |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| process-created | <b>T1070 - Indicator Removal on Host</b><br> ↳ <b>A-ETW-Trace-Disable</b>: Event tracing has been disabled, possible logging evasion on this asset<br> ↳ <b>ETW-Trace-Disable</b>: Event tracing has been disabled, possible logging evasion<br> ↳ <b>Sysmon-Driver-Unload</b>: Possible Sysmon driver unloaded.<br><br><b>T1070.001 - Indicator Removal on Host: Clear Windows Event Logs</b><br> ↳ <b>A-EventLog-Tamper</b>: EventLog has been tampered with on this asset<br> ↳ <b>EventLog-Tamper</b>: EventLog has been tampered with |        |