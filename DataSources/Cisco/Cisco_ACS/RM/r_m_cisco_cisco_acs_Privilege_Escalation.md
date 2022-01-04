Vendor: Cisco
=============
### Product: [Cisco ACS](../ds_cisco_cisco_acs.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     3      |      3      |    3    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                   | Models                                                             |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| account-lockout | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-01</b>: Account lockout on an asset that belongs to this user<br><br><b>T1555.005 - T1555.005</b><br> ↳ <b>SEQ-UH-01</b>: Account lockout on an asset that belongs to this user                                                                                                                                           |                                                                    |
| app-activity    | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>EM-InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions |