Vendor: McAfee
==============
### Product: [McAfee Endpoint Security](../ds_mcafee_mcafee_endpoint_security.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |     11      |   11    |

| Event Type       | Rules                                                                                                                                                                                                             | Models                                 |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| failed-app-login | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                     |                                        |
| file-write       | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                 |                                        |
| remote-logon     | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |  • <b>AL-HT-EXEC</b>: Executive Assets |
| security-alert   | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                                                                                     |                                        |