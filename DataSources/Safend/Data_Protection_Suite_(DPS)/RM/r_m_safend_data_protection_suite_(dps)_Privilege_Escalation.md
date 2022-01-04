Vendor: Safend
==============
### Product: [Data Protection Suite (DPS)](../ds_safend_data_protection_suite_(dps).md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     2      |      2      |    2    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                | Models                                                                                   |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| usb-write  | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session |