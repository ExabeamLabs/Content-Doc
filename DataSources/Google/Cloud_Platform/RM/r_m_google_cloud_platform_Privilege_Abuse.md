Vendor: Google
==============
### Product: [Cloud Platform](../ds_google_cloud_platform.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   4    |     5      |     10      |   10    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity    | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>EM-InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application<br> ↳ <b>APP-AT-PRIV</b>: Non-privileged user performing privileged application activity |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions<br> • <b>APP-AT-PRIV</b>: Privileged application activities    |
| cloud-admin-activity        | <b>T1078.004 - Valid Accounts: Cloud Accounts</b><br> ↳ <b>CS-Admin-Activity-A</b>: Abnormal invocation of this specific admin activity<br><br><b>T1530 - Data from Cloud Storage Object</b><br> ↳ <b>CS-Policies-F</b>: First time seeing this cloud policy<br> ↳ <b>CS-Policies-A</b>: Abnormal cloud policy seen    |  • <b>CS-Admin-Activity</b>: Cloud administrative activities performed by user<br> • <b>CS-Policies</b>: Cloud Policies seen in the organization |
| cloud-admin-activity-failed | <b>T1078.004 - Valid Accounts: Cloud Accounts</b><br> ↳ <b>CS-Admin-Activity-A</b>: Abnormal invocation of this specific admin activity    |  • <b>CS-Admin-Activity</b>: Cloud administrative activities performed by user    |
| file-download    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| web-activity-allowed        | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity    |    |