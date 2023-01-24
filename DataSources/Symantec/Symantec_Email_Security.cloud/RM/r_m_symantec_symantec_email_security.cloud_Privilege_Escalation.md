Vendor: Symantec
================
### Product: [Symantec Email Security.cloud](../ds_symantec_symantec_email_security.cloud.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   3    |     8      |      6      |    6    |

| Event Type             | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Models                                                                                            |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| app-activity           | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>EM-InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions                                |
| process-created-failed | <b>T1012 - Query Registry</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity<br><br><b>T1056.004 - T1056.004</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity<br><br><b>T1070.004 - Indicator Removal on Host: File Deletion</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity<br><br><b>T1547.006 - T1547.006</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity<br><br><b>T1560 - Archive Collected Data</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity |  • <b>EPA-UP-TEMP</b>: Process executable TEMP directories for this user during endpoint activity |
| security-alert         | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session          |