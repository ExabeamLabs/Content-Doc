Vendor: LanScope
================
### Product: [LanScope Cat](../ds_lanscope_lanscope_cat.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     4      |      9      |    9    |

| Event Type           | Rules                                                                                                                                                                                                                                                                                     | Models                                 |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| app-activity         | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account |                                        |
| local-logon          | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset                                                                                                                                                                                              |  • <b>AL-HT-EXEC</b>: Executive Assets |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller                                                                                                                                   |                                        |