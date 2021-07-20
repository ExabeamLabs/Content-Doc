Vendor: Johnson Controls
========================
### Product: [Johnson Controls P2000](../ds_johnson_controls_johnson_controls_p2000.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      5      |    5    |

| Event Type     | Rules                                                                                                         | Models |
| -------------- | ------------------------------------------------------------------------------------------------------------- | ------ |
| app-login      | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account |        |
| failed-logon   | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |        |
| security-alert | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |        |