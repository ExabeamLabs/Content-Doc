Vendor: LanScope
================
### Product: [LanScope Cat](../ds_lanscope_lanscope_cat.md)
### Use-Case: [Executive Account Activity](../../../../UseCases/uc_executive_account_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      9      |    9    |

| Event Type   | Rules                                                                                                                                                                | Models                                 |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| app-activity | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user |                                        |
| local-logon  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset                                                                         |  • <b>AL-HT-EXEC</b>: Executive Assets |