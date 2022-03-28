Vendor: Dell
============
### Product: [One Identity Manager](../ds_dell_one_identity_manager.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      3      |    3    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| account-password-change | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user |  • <b>AE-UA</b>: All activity for users |
| account-switch          | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user |  • <b>AE-UA</b>: All activity for users |