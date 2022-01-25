Vendor: Citrix
==============
### Product: [Citrix XenDesktop](../ds_citrix_citrix_xendesktop.md)
### Use-Case: [Account Switch](../../../../UseCases/uc_account_switch.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      1      |    1    |

| Event Type   | Rules                                                                                                                                                                                | Models                                                |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user |  • <b>AS-PV-OA</b>: Password retrieval based accounts |