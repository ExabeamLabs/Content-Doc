Vendor: Microsoft
=================
### Product: [Microsoft Azure](../ds_microsoft_microsoft_azure.md)
### Use-Case: [Permission Changes](../../../../UseCases/uc_permission_changes.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |     18      |   18    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                             | Models                                                             |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| app-activity    | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions |
| process-created | <b>T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification</b><br> ↳ <b>File-Folder-Perm-Mod</b>: The permissions of a file or folder were modified.                                                                                                                                                         |                                                                    |