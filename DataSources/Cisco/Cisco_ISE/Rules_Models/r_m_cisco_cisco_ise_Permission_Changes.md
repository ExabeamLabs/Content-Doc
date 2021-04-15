Vendor: Cisco
=============
### Product: [Cisco ISE](../ds_cisco_cisco_ise.md)
### Use-Case: [Permission Changes](../../../../UseCases/uc_permission_changes.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     1      |      9      |    9    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                             | Models                                                                              |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| app-activity | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions                  |
| vpn-logout   | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user.                                                                                                                                                                                                     |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user. |