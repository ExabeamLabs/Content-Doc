Vendor: FireEye
===============
### Product: [FireEye Email Threat Prevention (ETP)](../ds_fireeye_fireeye_email_threat_prevention_(etp).md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      3      |    3    |

| Event Type                | Rules                                                                                                         | Models |
| ------------------------- | ------------------------------------------------------------------------------------------------------------- | ------ |
| dlp-email-alert-in        | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account |        |
| dlp-email-alert-in-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account |        |
| security-alert            | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |        |