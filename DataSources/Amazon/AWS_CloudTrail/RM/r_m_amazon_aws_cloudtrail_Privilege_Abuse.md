Vendor: Amazon
==============
### Product: [AWS CloudTrail](../ds_amazon_aws_cloudtrail.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  10   |   4    |     5      |      9      |    9    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| account-password-change     | <b>T1098 - Account Manipulation</b><br> ↳ <b>AM-UA-APLocU-F</b>: First account password change for local user    |    |
| app-activity    | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>EM-InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application<br> ↳ <b>APP-AT-PRIV</b>: Non-privileged user performing privileged application activity |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions<br> • <b>APP-AT-PRIV</b>: Privileged application activities    |
| app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application    |    |
| cloud-admin-activity        | <b>T1078.004 - Valid Accounts: Cloud Accounts</b><br> ↳ <b>CS-Admin-Activity-A</b>: Abnormal invocation of this specific admin activity<br><br><b>T1530 - Data from Cloud Storage Object</b><br> ↳ <b>CS-Policies-F</b>: First time seeing this cloud policy<br> ↳ <b>CS-Policies-A</b>: Abnormal cloud policy seen    |  • <b>CS-Admin-Activity</b>: Cloud administrative activities performed by user<br> • <b>CS-Policies</b>: Cloud Policies seen in the organization |
| cloud-admin-activity-failed | <b>T1078.004 - Valid Accounts: Cloud Accounts</b><br> ↳ <b>CS-Admin-Activity-A</b>: Abnormal invocation of this specific admin activity    |  • <b>CS-Admin-Activity</b>: Cloud administrative activities performed by user    |