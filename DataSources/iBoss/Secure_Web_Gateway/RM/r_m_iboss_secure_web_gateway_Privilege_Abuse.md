Vendor: iBoss
=============
### Product: [Secure Web Gateway](../ds_iboss_secure_web_gateway.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     3      |      2      |    2    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| account-deleted      | <b>T1531 - Account Access Removal</b><br> ↳ <b>AM-UA-AD-F</b>: First account deletion activity for user    |  • <b>AE-UA</b>: All activity for users |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity |    |