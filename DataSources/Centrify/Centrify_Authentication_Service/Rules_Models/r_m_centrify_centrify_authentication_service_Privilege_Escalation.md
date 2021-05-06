Vendor: Centrify
================
### Product: [Centrify Authentication Service](../ds_centrify_centrify_authentication_service.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |      4      |    4    |

| Event Type   | Rules                                                                                                                                                                                | Models                                                |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| failed-logon | <b>T1210 - Exploitation of Remote Services</b><br> ↳ <b>A-Suspicious-Zerologon</b>: Failed authentication attempt on this asset.                                                     |                                                       |
| local-logon  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user |  • <b>AS-PV-OA</b>: Password retrieval based accounts |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user |  • <b>AS-PV-OA</b>: Password retrieval based accounts |