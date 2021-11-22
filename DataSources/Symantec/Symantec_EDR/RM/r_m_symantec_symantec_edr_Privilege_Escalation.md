Vendor: Symantec
================
### Product: [Symantec EDR](../ds_symantec_symantec_edr.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     2      |      6      |    6    |

| Event Type   | Rules                                                                                                                                                                                | Models                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| failed-logon | <b>T1210 - Exploitation of Remote Services</b><br> ↳ <b>A-Suspicious-Zerologon</b>: Failed authentication attempt on this asset.                                                     |                                                                                             |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user |  • <b>DC18</b>: Secondary accounts<br> • <b>AS-PV-OA</b>: Password retrieval based accounts |