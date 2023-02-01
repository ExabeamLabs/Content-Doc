Vendor: SentinelOne
===================
### Product: [Singularity](../ds_sentinelone_singularity.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  10   |   3    |         7          |      9      |    9    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity         | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-AT-PRIV</b>: Non-privileged user performing privileged application activity    |  • <b>APP-AT-PRIV</b>: Privileged application activities    |
| file-alert    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| file-delete          | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| file-read    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| file-write    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| process-created      | <b>T1482 - Domain Trust Discovery</b><br> ↳ <b>A-Trickbot-Recon</b>: Trickbot malware domain recon activity on this asset<br> ↳ <b>Trickbot-Recon</b>: Trickbot malware domain recon activity    |    |
| security-alert       | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive    |    |
| task-created         | <b>T1053.005 - Scheduled Task/Job: Scheduled Task</b><br> ↳ <b>WTC-HT-EXEC</b>: Non-Executive user created a scheduled task/service on executive asset<br> ↳ <b>WTC-HT-PRIV</b>: Non-Privileged user created a scheduled task/service on privileged asset<br><br><b>T1543.003 - Create or Modify System Process: Windows Service</b><br> ↳ <b>WTC-HT-EXEC</b>: Non-Executive user created a scheduled task/service on executive asset<br> ↳ <b>WTC-HT-PRIV</b>: Non-Privileged user created a scheduled task/service on privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets<br> • <b>AL-HT-EXEC</b>: Executive Assets |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller<br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller    |    |