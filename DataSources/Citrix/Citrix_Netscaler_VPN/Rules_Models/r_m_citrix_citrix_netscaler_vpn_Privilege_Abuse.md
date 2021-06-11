Vendor: Citrix
==============
### Product: [Citrix Netscaler VPN](../ds_citrix_citrix_netscaler_vpn.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   3    |     3      |      6      |    6    |

| Event Type    | Rules                                                                                                                                                                                                                     | Models                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| remote-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1021 - Remote Services</b><b>T1078 - Valid Accounts</b><br> ↳ <b>RA-HT-EXEC-new</b>: New user remote access to executive asset |  • <b>AL-HT-EXEC</b>: Executive Assets                                                 |
| remote-logon  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset<br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br> ↳ <b>DC18-new</b>: Account switch by new user          |  • <b>AL-HT-EXEC</b>: Executive Assets<br> • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| vpn-logout    | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user.                                                             |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user.    |