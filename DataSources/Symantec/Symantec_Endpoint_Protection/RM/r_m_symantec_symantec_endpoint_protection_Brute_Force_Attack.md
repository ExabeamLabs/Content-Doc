Vendor: Symantec
================
### Product: [Symantec Endpoint Protection](../ds_symantec_symantec_endpoint_protection.md)
### Use-Case: [Brute Force Attack](../../../../UseCases/uc_brute_force_attack.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     3      |      8      |    8    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                                                                             | Models                                                |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| failed-logon | <b>T1021.001 - Remote Services: Remote Desktop Protocol</b><br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user<br><br><b>T1110 - Brute Force</b><br> ↳ <b>A-FL-MULTI-USERS-SRC</b>: The same host failed to login to multiple users<br> ↳ <b>A-FL-MULTI-DEST</b>: Failed logins to multiple destinations from host<br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user |                                                       |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user                                                                                                                                                                                                                                                                                                |  • <b>AS-PV-OA</b>: Password retrieval based accounts |