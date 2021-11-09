Vendor: Sailpoint
=================
### Product: [IdentityNow](../ds_sailpoint_identitynow.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      4      |    4    |

| Event Type | Rules                                                                                                         | Models                                                          |
| ---------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| app-login  | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account |                                                                 |
| vpn-logout | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user   |  • <b>WPA-UACount</b>: Count of admin privilege events for user |