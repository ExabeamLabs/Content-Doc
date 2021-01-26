Vendor: Synology NAS
====================
Product: Synology NAS
---------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  13   |   4    |     5      |      3      |    3    |

|                                 Use-Case                                  | Activity Types                           | Event Types/Parsers                                                                                                                                                 | MITRE TTP                                                                      | Content                                             |
|:-------------------------------------------------------------------------:| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------- |
| [Compromised Credentials](../UseCases/usecase_compromised_credentials.md) | <ul><li>Asset Logon and Access</li></ul> |  share-access<br> ↳ [nas-share-access-1](../Parsers/parserContent_nas-share-access-1.md)<br> ↳ [nas-share-access](../Parsers/parserContent_nas-share-access.md)<br> | T1068 - Exploitation for Privilege Escalation<br>T1087 - Account Discovery<br> | <ul><li>2 Rules</li></ul>                           |
|        [Lateral Movement](../UseCases/usecase_lateral_movement.md)        | <ul><li>Asset Logon and Access</li></ul> |  share-access<br> ↳ [nas-share-access-1](../Parsers/parserContent_nas-share-access-1.md)<br> ↳ [nas-share-access](../Parsers/parserContent_nas-share-access.md)<br> | T1077 - T1077<br>                                                              | <ul><li>9 Rules</li></ul><ul><li>4 Models</li></ul> |
|     [Privileged Activity](../UseCases/usecase_privileged_activity.md)     | <ul><li>Asset Logon and Access</li></ul> |  share-access<br> ↳ [nas-share-access-1](../Parsers/parserContent_nas-share-access-1.md)<br> ↳ [nas-share-access](../Parsers/parserContent_nas-share-access.md)<br> | T1068 - Exploitation for Privilege Escalation<br>T1087 - Account Discovery<br> | <ul><li>2 Rules</li></ul>                           |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation                                                                       | Defense Evasion | Credential Access | Discovery                                                              | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | ------------------------------------------------------------------------------------------ | --------------- | ----------------- | ---------------------------------------------------------------------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           |             | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> |                 |                   | [Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br> |                  |            |                     |              |        |