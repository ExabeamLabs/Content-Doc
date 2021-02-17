Vendor: Check Point Software
============================
### Product: [Check Point NGFW](../ds_check_point_software_check_point_ngfw.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |     10      |   10    |

| Event Type  | Rules                                                                                             | Models                                       |
| ----------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| app-login   | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-SA-NC</b>: New service account access to application |                                              |
| local-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset   |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |