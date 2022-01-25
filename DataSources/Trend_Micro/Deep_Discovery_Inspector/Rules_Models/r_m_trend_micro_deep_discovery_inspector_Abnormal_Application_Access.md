Vendor: Trend Micro
===================
### Product: [Deep Discovery Inspector](../ds_trend_micro_deep_discovery_inspector.md)
### Use-Case: [Abnormal Application Access](../../../../UseCases/uc_abnormal_application_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   4    |     1      |      3      |    3    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                           | Models                                                                                                                                                                                     |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| app-login  | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-AppU-F</b>: First login to an application for a user with no history<br> ↳ <b>APP-AppG-F</b>: First login to an application for group<br> ↳ <b>APP-GApp-A</b>: Abnormal login to an application for group<br> ↳ <b>APP-UAg-3</b>: More than two new user agents used by the user in the same session |  • <b>APP-UAg</b>: User Agent Strings<br> • <b>APP-GApp</b>: Group Logons to Applications<br> • <b>APP-AppG</b>: Groups per Application<br> • <b>APP-AppU</b>: User Logons to Applications |