Vendor: Citrix
==============
### Product: [Citrix XenApp](../ds_citrix_citrix_xenapp.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |      2      |    2    |

| Event Type   | Rules                                                                                                                                                                                                                | Models                                       |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-SA-NC</b>: New service account access to application                                                                                                                    |                                              |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |