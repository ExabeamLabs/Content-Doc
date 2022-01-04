Vendor: ESET
============
### Product: [ESET Endpoint Security](../ds_eset_eset_endpoint_security.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     3      |      7      |    7    |

| Event Type     | Rules                                                                                                                                                                                                                                                                                                                                | Models                                                                                   |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| failed-logon   | <b>T1210 - Exploitation of Remote Services</b><br> ↳ <b>A-Suspicious-Zerologon</b>: Failed authentication attempt on this asset.                                                                                                                                                                                                     |                                                                                          |
| network-alert  | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session |
| security-alert | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session |