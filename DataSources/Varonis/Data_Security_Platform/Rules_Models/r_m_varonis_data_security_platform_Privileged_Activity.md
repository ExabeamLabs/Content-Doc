Vendor: Varonis
===============
### Product: [Data Security Platform](../ds_varonis_data_security_platform.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      9      |    9    |

| Event Type             | Rules                                                                                                             | Models                                                          |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| file-delete            | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |                                                                 |
| file-permission-change | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |                                                                 |
| file-read              | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |                                                                 |
| file-write             | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |                                                                 |
| vpn-logout             | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user       |  • <b>WPA-UACount</b>: Count of admin privilege events for user |