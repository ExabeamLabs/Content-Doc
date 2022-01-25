Vendor: CA Technologies
=======================
### Product: [CA Privileged Access Manager Server Control](../ds_ca_technologies_ca_privileged_access_manager_server_control.md)
### Use-Case: [Abnormal Application Access](../../../../UseCases/uc_abnormal_application_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   4    |     1      |      5      |    5    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                           | Models                                                                                                                                                                                     |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| app-login  | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-AppU-F</b>: First login to an application for a user with no history<br> ↳ <b>APP-AppG-F</b>: First login to an application for group<br> ↳ <b>APP-GApp-A</b>: Abnormal login to an application for group<br> ↳ <b>APP-UAg-3</b>: More than two new user agents used by the user in the same session |  • <b>APP-UAg</b>: User Agent Strings<br> • <b>APP-GApp</b>: Group Logons to Applications<br> • <b>APP-AppG</b>: Groups per Application<br> • <b>APP-AppU</b>: User Logons to Applications |