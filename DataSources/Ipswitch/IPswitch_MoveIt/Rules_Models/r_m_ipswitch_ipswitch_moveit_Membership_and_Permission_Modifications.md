Vendor: Ipswitch
================
### Product: [IPswitch MoveIt](../ds_ipswitch_ipswitch_moveit.md)
### Use-Case: [Membership and Permission Modifications](../../../../UseCases/uc_membership_and_permission_modifications.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     1      |      5      |    5    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                             | Models                                                             |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| app-activity | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions |