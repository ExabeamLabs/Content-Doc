Vendor: Juniper Networks
========================
### Product: [Juniper VPN](../ds_juniper_networks_juniper_vpn.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   2    |     4      |      6      |    6    |

| Event Type      | Rules                                                                                                                                                                                                               | Models                                                                              |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| account-deleted | <b>T1531 - Account Access Removal</b><br> ↳ <b>AM-UA-AD-F</b>: First account deletion activity for user<br><br><b>T1098 - Account Manipulation</b><br> ↳ <b>A-ACCT-CR-DEL</b>: Account created and deleted on asset |  • <b>AE-UA</b>: All activity for users                                             |
| vpn-login       | <b>T1133 - External Remote Services</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account                                                                                                          |                                                                                     |
| vpn-logout      | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user.                                                       |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user. |