Vendor: Cisco
=============
### Product: [Cisco Adaptive Security Appliance](../ds_cisco_cisco_adaptive_security_appliance.md)
### Use-Case: [Permission Changes](../../../../UseCases/uc_permission_changes.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |     13      |   13    |

| Event Type      | Rules                                                                                                                                                                                                     | Models                                                                              |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| process-created | <b>T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification</b><br> ↳ <b>File-Folder-Perm-Mod</b>: The permissions of a file or folder were modified. |                                                                                     |
| vpn-logout      | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user.                                             |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user. |