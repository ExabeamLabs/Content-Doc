Vendor: Dropbox
===============
### Product: [Dropbox](../ds_dropbox_dropbox.md)
### Use-Case: [Account Manipulation](../../../../UseCases/uc_account_manipulation.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  10   |   7    |         2          |      2      |    2    |

| Event Type   | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>EM-InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions    |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions    |
| vpn-logout   | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user.<br><br><b>T1484 - Group Policy Modification</b><br> ↳ <b>FDS-Count</b>: Abnormal number of failed directory service events in the organization<br> ↳ <b>FDS-GCount</b>: Abnormal number of failed directory service events in the peer group<br> ↳ <b>FDS-UCount</b>: Abnormal number of failed directory service events in the user<br> ↳ <b>DS-Count</b>: Abnormal number of directory service events in the organization<br> ↳ <b>DS-GCount</b>: Abnormal number of directory service events in the peer group<br> ↳ <b>DS-UCount</b>: Abnormal number of directory service events in the user |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user.<br> • <b>DS-UCount</b>: Count of directory service activity events in the user<br> • <b>DS-GCount</b>: Count of directory service activity events in the peer group<br> • <b>DS-Count</b>: Count of directory service activity events in the organization<br> • <b>FDS-UCount</b>: Count of failed directory service activity events in the user<br> • <b>FDS-GCount</b>: Count of failed directory service activity events in the peer group<br> • <b>FDS-Count</b>: Count of failed directory service activity events in the organization |