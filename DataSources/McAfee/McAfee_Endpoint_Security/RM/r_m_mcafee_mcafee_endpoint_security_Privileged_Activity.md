Vendor: McAfee
==============
### Product: [McAfee Endpoint Security](../ds_mcafee_mcafee_endpoint_security.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  14   |   5    |     3      |      9      |    9    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| dlp-email-alert-in-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account    |    |
| file-write    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| local-logon    | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-F-F-CS</b>: First logon to a critical system for user<br> ↳ <b>AL-F-A-CS</b>: Abnormal logon to a critical system for user<br> ↳ <b>AL-UH-CS-NC</b>: Logon to a critical system for a user with no information<br> ↳ <b>AL-OU-F-CS</b>: First logon to a critical system that user has not previously accessed<br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset<br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br><br><b>T1078.002 - T1078.002</b><br> ↳ <b>AL-F-F-DC-G</b>: First logon to a Domain Controller for peer group<br> ↳ <b>AL-F-A-DC-G</b>: Abnormal logon to a Domain Controller for Peer Group<br> ↳ <b>AL-UH-F-DC</b>: First logon to this Domain Controller for user<br> ↳ <b>AL-UH-A-DC</b>: Abnormal logon to a Domain Controller that user has not accessed often previously<br> ↳ <b>AL-UH-DC-NC</b>: Logon to a Domain Controller for user with no information |  • <b>AL-HT-EXEC</b>: Executive Assets<br> • <b>AL-HT-PRIV</b>: Privilege Users Assets<br> • <b>RA-UH</b>: Assets accessed by this user remotely<br> • <b>AL-UH-DC</b>: Logons to Domain Controllers<br> • <b>AL-OU-CS</b>: Logon to critical servers |
| security-alert    | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive    |    |