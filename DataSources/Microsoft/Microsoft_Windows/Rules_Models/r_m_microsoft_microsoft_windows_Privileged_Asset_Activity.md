Vendor: Microsoft
=================
### Product: [Microsoft Windows](../ds_microsoft_microsoft_windows.md)
### Use-Case: [Privileged Asset Activity](../../../../UseCases/uc_privileged_asset_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     3      |     57      |   57    |

| Event Type      | Rules                                                                                                                                                                                                                       | Models                                       |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| local-logon     | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset                                                                                                                             |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| ntlm-logon      | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset                                                                                                                             |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| remote-logon    | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset                                                                                                                             |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| service-created | <b>T1053.005 - Scheduled Task/Job: Scheduled Task</b><b>T1543.003 - Create or Modify System Process: Windows Service</b><br> ↳ <b>WTC-HT-PRIV</b>: Non-Privileged user created a scheduled task/service on privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| task-created    | <b>T1053.005 - Scheduled Task/Job: Scheduled Task</b><b>T1543.003 - Create or Modify System Process: Windows Service</b><br> ↳ <b>WTC-HT-PRIV</b>: Non-Privileged user created a scheduled task/service on privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |