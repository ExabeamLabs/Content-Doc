Vendor: Juniper Networks
========================
### Product: [Juniper SRX](../ds_juniper_networks_juniper_srx.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |     12      |   12    |

| Event Type      | Rules                                                                                                                                                         | Models                                                                              |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| account-deleted | <b>T1098 - Account Manipulation</b><br> ↳ <b>A-ACCT-CR-DEL</b>: Account created and deleted on asset                                                          |                                                                                     |
| vpn-logout      | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user. |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user. |