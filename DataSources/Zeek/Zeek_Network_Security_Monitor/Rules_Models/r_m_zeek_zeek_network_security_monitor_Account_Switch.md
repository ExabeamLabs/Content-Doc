Vendor: Zeek
============
### Product: [Zeek Network Security Monitor](../ds_zeek_zeek_network_security_monitor.md)
### Use-Case: [Account Switch](../../../../UseCases/uc_account_switch.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |     24      |   24    |

| Event Type     | Rules                                                                                                                                                                                | Models                                                |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| kerberos-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user |  • <b>AS-PV-OA</b>: Password retrieval based accounts |
| ntlm-logon     | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user |  • <b>AS-PV-OA</b>: Password retrieval based accounts |
| remote-access  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user |  • <b>AS-PV-OA</b>: Password retrieval based accounts |
| remote-logon   | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user |  • <b>AS-PV-OA</b>: Password retrieval based accounts |