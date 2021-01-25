Vendor: Quest Software
======================
Product: Change Auditor
-----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  12   |   8    |     3      |      2      |    2    |

|               Use-Case                | Activity Types                                                         | Event Types/Parsers                                                                                                                                                                                                   | MITRE TTP                                                                                                          | Content                                              |
|:-------------------------------------:| ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Critical System Activity</li><li>Privileged Activity</li></ul> |  ds-access<br> ↳ [s-quest-directory-access](../Parsers/parserContent_s-quest-directory-access.md)<br><br> failed-ds-access<br> ↳ [q-quest-directory-access](../Parsers/parserContent_q-quest-directory-access.md)<br> | T1003 - OS Credential Dumping<br>T1068 - Exploitation for Privilege Escalation<br>T1098 - Account Manipulation<br> | <ul><li>12 Rules</li></ul><ul><li>8 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence                                                               | Privilege Escalation                                                                       | Defense Evasion | Credential Access                                                          | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | --------------- | -------------------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           | [Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br> | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> |                 | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> |           |                  |            |                     |              |        |