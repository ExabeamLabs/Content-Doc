Vendor: Check Point
===================
### Product: [Threat Prevention](../ds_check_point_threat_prevention.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      6      |    6    |

| Event Type     | Rules                                                                                                         | Models                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| security-alert | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |                                                                 |
| vpn-logout     | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user   |  • <b>WPA-UACount</b>: Count of admin privilege events for user |