Vendor: ESET
============
### Product: [ESET Endpoint Security](../ds_eset_eset_endpoint_security.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      7      |    7    |

| Event Type     | Rules                                                                                                         | Models |
| -------------- | ------------------------------------------------------------------------------------------------------------- | ------ |
| app-login      | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-SA-NC</b>: New service account access to application             |        |
| failed-logon   | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |        |
| security-alert | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |        |