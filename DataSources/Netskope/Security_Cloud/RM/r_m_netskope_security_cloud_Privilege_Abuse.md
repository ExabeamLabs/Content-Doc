Vendor: Netskope
================
### Product: [Security Cloud](../ds_netskope_security_cloud.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   8   |   2    |     3      |     16      |   16    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity    | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>EM-InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application<br> ↳ <b>APP-AT-PRIV</b>: Non-privileged user performing privileged application activity |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions<br> • <b>APP-AT-PRIV</b>: Privileged application activities |
| app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application    |    |
| dlp-email-alert-out    | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account    |    |
| failed-app-login       | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account    |    |
| file-delete    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| file-download          | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| file-permission-change | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| file-read    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| file-upload    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| file-write    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| web-activity-allowed   | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity    |    |
| web-activity-denied    | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity    |    |