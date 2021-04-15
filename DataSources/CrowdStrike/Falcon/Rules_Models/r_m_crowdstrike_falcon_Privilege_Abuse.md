Vendor: CrowdStrike
===================
### Product: [Falcon](../ds_crowdstrike_falcon.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     3      |     27      |   27    |

| Event Type   | Rules                                                                                                                                                                                                                       | Models                                       |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| local-logon  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset                                                                                                                             |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset                                                                                                                             |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| task-created | <b>T1053.005 - Scheduled Task/Job: Scheduled Task</b><b>T1543.003 - Create or Modify System Process: Windows Service</b><br> ↳ <b>WTC-HT-PRIV</b>: Non-Privileged user created a scheduled task/service on privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |