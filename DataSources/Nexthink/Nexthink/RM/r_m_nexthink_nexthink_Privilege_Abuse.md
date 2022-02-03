Vendor: Nexthink
================
### Product: [Nexthink](../ds_nexthink_nexthink.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     2      |      1      |    1    |

| Event Type   | Rules    | Models    |
| ---- | ---- | ---- |
| task-created | <b>T1053.005 - Scheduled Task/Job: Scheduled Task</b><br> ↳ <b>WTC-HT-PRIV</b>: Non-Privileged user created a scheduled task/service on privileged asset<br><br><b>T1543.003 - Create or Modify System Process: Windows Service</b><br> ↳ <b>WTC-HT-PRIV</b>: Non-Privileged user created a scheduled task/service on privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |