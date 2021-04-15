Vendor: Citrix
==============
### Product: [Citrix Endpoint Management](../ds_citrix_citrix_endpoint_management.md)
### Use-Case: [Executive Account Activity](../../../../UseCases/uc_executive_account_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     3      |      2      |    2    |

| Event Type   | Rules                                                                                                                                                                                                             | Models                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| app-activity | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user                                              |                                        |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |  • <b>AL-HT-EXEC</b>: Executive Assets |