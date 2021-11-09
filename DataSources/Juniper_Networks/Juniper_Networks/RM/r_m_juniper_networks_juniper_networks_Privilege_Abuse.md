Vendor: Juniper Networks
========================
### Product: [Juniper Networks](../ds_juniper_networks_juniper_networks.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     3      |      4      |    4    |

| Event Type      | Rules                                                                                                                                                                                                               | Models                                  |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| account-deleted | <b>T1531 - Account Access Removal</b><br> ↳ <b>AM-UA-AD-F</b>: First account deletion activity for user<br><br><b>T1098 - Account Manipulation</b><br> ↳ <b>A-ACCT-CR-DEL</b>: Account created and deleted on asset |  • <b>AE-UA</b>: All activity for users |
| vpn-login       | <b>T1133 - External Remote Services</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account                                                                                                          |                                         |