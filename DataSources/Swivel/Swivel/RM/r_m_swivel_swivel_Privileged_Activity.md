Vendor: Swivel
==============
### Product: [Swivel](../ds_swivel_swivel.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     1      |      3      |    3    |

| Event Type  | Rules                                                                                                             | Models                                                          |
| ----------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| app-login   | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account     |                                                                 |
| file-upload | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |                                                                 |
| vpn-logout  | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user       |  • <b>WPA-UACount</b>: Count of admin privilege events for user |