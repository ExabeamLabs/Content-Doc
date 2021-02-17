Vendor: Quest Software
======================
Product: Change Auditor
-----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      2      |    2    |

|                Use-Case                | Activity Types                             | Event Types/Parsers                                                                                                                                                                                                                                                                                 | MITRE TTP                         | Content                                                                                                        |
|:--------------------------------------:| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) | <ul><li>Critical System Activity</li></ul> |  ds-access<br> ↳ [s-quest-directory-access](Parsers/parserContent_s-quest-directory-access.md)<br> ↳ [q-quest-directory-access](Parsers/parserContent_q-quest-directory-access.md)<br><br> failed-ds-access<br> ↳ [q-quest-directory-access](Parsers/parserContent_q-quest-directory-access.md)<br> | T1003 - OS Credential Dumping<br> | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_quest_software_change_auditor_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access                                                          | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | -------------------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> |           |                  |            |                     |              |        |