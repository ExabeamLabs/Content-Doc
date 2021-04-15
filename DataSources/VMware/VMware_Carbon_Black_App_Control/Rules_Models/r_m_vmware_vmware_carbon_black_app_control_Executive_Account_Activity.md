Vendor: VMware
==============
### Product: [VMware Carbon Black App Control](../ds_vmware_vmware_carbon_black_app_control.md)
### Use-Case: [Executive Account Activity](../../../../UseCases/uc_executive_account_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |     16      |   16    |

| Event Type     | Rules                                                                                                         | Models                                 |
| -------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| local-logon    | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset                  |  • <b>AL-HT-EXEC</b>: Executive Assets |
| security-alert | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |                                        |