Vendor: Synology NAS
====================
Product: Synology NAS
---------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   6    |     3      |      1      |    1    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                                                                           | MITRE TTP                                                                      | Content                                                                                                               |
|:--------------------------------------------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  share-access<br> ↳ [nas-share-access-1](Parsers/parserContent_nas-share-access-1.md)<br> ↳ [nas-share-access](Parsers/parserContent_nas-share-access.md)<br> | T1068 - Exploitation for Privilege Escalation<br>T1087 - Account Discovery<br> | [<ul><li>2 Rules</li></ul>](Rules_Models/r_m_synology_nas_synology_nas_Compromised_Credentials.md)                    |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  share-access<br> ↳ [nas-share-access-1](Parsers/parserContent_nas-share-access-1.md)<br> ↳ [nas-share-access](Parsers/parserContent_nas-share-access.md)<br> | T1077 - T1077<br>                                                              | [<ul><li>9 Rules</li></ul><ul><li>6 Models</li></ul>](Rules_Models/r_m_synology_nas_synology_nas_Lateral_Movement.md) |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  share-access<br> ↳ [nas-share-access-1](Parsers/parserContent_nas-share-access-1.md)<br> ↳ [nas-share-access](Parsers/parserContent_nas-share-access.md)<br> | T1068 - Exploitation for Privilege Escalation<br>T1087 - Account Discovery<br> | [<ul><li>2 Rules</li></ul>](Rules_Models/r_m_synology_nas_synology_nas_Privileged_Activity.md)                        |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation                                                                       | Defense Evasion | Credential Access | Discovery                                                              | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | ------------------------------------------------------------------------------------------ | --------------- | ----------------- | ---------------------------------------------------------------------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           |             | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> |                 |                   | [Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br> |                  |            |                     |              |        |