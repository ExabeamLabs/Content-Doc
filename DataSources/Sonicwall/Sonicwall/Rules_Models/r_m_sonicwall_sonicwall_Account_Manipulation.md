Vendor: Sonicwall
=================
### Product: [Sonicwall](../ds_sonicwall_sonicwall.md)
### Use-Case: [Account Manipulation](../../../../UseCases/uc_account_manipulation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      6      |    6    |

| Event Type   | Rules                                                                                                                                                         | Models                                                                              |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>DC18-new</b>: Account switch by new user                                                                               |                                                                                     |
| vpn-logout   | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user. |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user. |