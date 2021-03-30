Vendor: Synology NAS
====================
Product: Synology NAS
---------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  10   |   5    |     3      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                                                                           | MITRE TTP                                                                                       | Content                                                                                                     |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  share-access<br> ↳ [nas-share-access-1](Parsers/parserContent_nas-share-access-1.md)<br> ↳ [nas-share-access](Parsers/parserContent_nas-share-access.md)<br> | T1068 - Exploitation for Privilege Escalation<br>T1077 - T1077<br>T1087 - Account Discovery<br> | [<ul><li>10 Rules</li></ul><ul><li>5 Models</li></ul>](Rules_Models/r_m_synology_nas_synology_nas_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation                                                                       | Defense Evasion | Credential Access | Discovery                                                              | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | ------------------------------------------------------------------------------------------ | --------------- | ----------------- | ---------------------------------------------------------------------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           |             | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> |                 |                   | [Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br> |                  |            |                     |              |        |