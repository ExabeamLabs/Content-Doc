Vendor: Kaspersky
=================
### Product: [Kaspersky AV](../ds_kaspersky_kaspersky_av.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      3      |    3    |

| Event Type     | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity   | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-AT-PRIV</b>: Non-privileged user performing privileged application activity |  • <b>APP-AT-PRIV</b>: Privileged application activities |
| file-alert     | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| security-alert | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive    |    |