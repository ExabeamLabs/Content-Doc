Vendor: Onapsis
===============
### Product: [Onapsis](../ds_onapsis_onapsis.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      4      |    4    |

| Event Type       | Rules                                                                                                                                                                                                                                                                                          | Models                              |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| app-login        | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-UTi</b>: Abnormal user activity time<br> ↳ <b>APP-AppSz-F</b>: First application access from network zone<br><br><b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user |  • <b>UA-UC</b>: Countries for user |
| failed-app-login | <b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: Failed activity from a new country                                                                                                                                                                                               |  • <b>UA-UC</b>: Countries for user |