Vendor: Trend Micro
===================
### Product: [OfficeScan](../ds_trend_micro_officescan.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     5      |      7      |    7    |

| Event Type               | Rules                                                                                                                                                                                       | Models |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| dlp-email-alert-in       | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                               |        |
| dlp-email-alert-out      | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                               |        |
| privileged-object-access | <b>T1543.003 - Create or Modify System Process: Windows Service</b><br> ↳ <b>SCM-Database-Privileged-Operation</b>: Privileged operations performed by non-system user on the SCM database. |        |
| security-alert           | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                                                               |        |
| web-activity-allowed     | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller                                     |        |