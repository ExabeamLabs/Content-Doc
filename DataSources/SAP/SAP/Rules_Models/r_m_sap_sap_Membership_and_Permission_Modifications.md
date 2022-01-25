Vendor: SAP
===========
### Product: [SAP](../ds_sap_sap.md)
### Use-Case: [Membership and Permission Modifications](../../../../UseCases/uc_membership_and_permission_modifications.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   2    |     2      |      9      |    9    |

| Event Type       | Rules                                                                                                                                                                                                                                                                                                                                                             | Models                                                             |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| account-creation | <b>T1098 - Account Manipulation</b><br> ↳ <b>AM-GA-new</b>: First account management activity for group of a new user                                                                                                                                                                                                                                             |  • <b>AE-GA</b>: All activity for peer groups                      |
| app-activity     | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions |