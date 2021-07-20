Vendor: BeyondTrust
===================
### Product: [BeyondTrust](../ds_beyondtrust_beyondtrust.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     3      |      5      |    5    |

| Event Type        | Rules                                                                                                                                                                                                                                                                                     | Models |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity      | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account |        |
| app-login         | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                                                                                             |        |
| failed-app-login  | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                                                                                             |        |
| privileged-access | <b>T1543.003 - Create or Modify System Process: Windows Service</b><br> ↳ <b>SCM-Database-Privileged-Operation</b>: Privileged operations performed by non-system user on the SCM database.                                                                                               |        |