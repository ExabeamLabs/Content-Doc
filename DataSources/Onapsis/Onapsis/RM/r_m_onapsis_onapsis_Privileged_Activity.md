Vendor: Onapsis
===============
### Product: [Onapsis](../ds_onapsis_onapsis.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |      4      |    4    |

| Event Type     | Rules                                                                                                         | Models                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| app-login      | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account |                                                                 |
| security-alert | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |                                                                 |
| vpn-logout     | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user   |  • <b>WPA-UACount</b>: Count of admin privilege events for user |