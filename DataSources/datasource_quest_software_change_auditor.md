Vendor: Quest Software
======================
Product: Change Auditor
-----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     2      |      4      |    4    |

|                                 Use-Case                                  | Activity Types                             | Event Types/Parsers                                                                                                                                                                                                   | MITRE TTP                         | Content                                             |
|:-------------------------------------------------------------------------:| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | --------------------------------------------------- |
| [Compromised Credentials](../UseCases/usecase_compromised_credentials.md) | <ul><li>Critical System Activity</li></ul> |  ds-access<br> ↳ [s-quest-directory-access](../Parsers/parserContent_s-quest-directory-access.md)<br><br> failed-ds-access<br> ↳ [q-quest-directory-access](../Parsers/parserContent_q-quest-directory-access.md)<br> | T1003 - OS Credential Dumping<br> | <ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul> |
|     [Privileged Activity](../UseCases/usecase_privileged_activity.md)     | <ul><li>Critical System Activity</li></ul> |  ds-access<br> ↳ [s-quest-directory-access](../Parsers/parserContent_s-quest-directory-access.md)<br><br> failed-ds-access<br> ↳ [q-quest-directory-access](../Parsers/parserContent_q-quest-directory-access.md)<br> | T1003 - OS Credential Dumping<br> | <ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access                                                          | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | -------------------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> |           |                  |            |                     |              |        |