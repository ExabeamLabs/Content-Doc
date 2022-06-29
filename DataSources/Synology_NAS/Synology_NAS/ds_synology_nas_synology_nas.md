Vendor: Synology NAS
====================
Product: Synology NAS
---------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  23   |   7    |     6      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  share-access<br> ↳[nas-share-access-1](Ps/pC_nasshareaccess1.md)<br> ↳[nas-share-access](Ps/pC_nasshareaccess.md)<br> | T1187 - Forced Authentication<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_synology_nas_synology_nas_Compromised_Credentials.md)    |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  share-access<br> ↳[nas-share-access-1](Ps/pC_nasshareaccess1.md)<br> ↳[nas-share-access](Ps/pC_nasshareaccess.md)<br> | T1021.002 - Remote Services: SMB/Windows Admin Shares<br>    | [<ul><li>14 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_synology_nas_synology_nas_Lateral_Movement.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  share-access<br> ↳[nas-share-access-1](Ps/pC_nasshareaccess1.md)<br> ↳[nas-share-access](Ps/pC_nasshareaccess.md)<br> | T1569 - System Services<br>T1569.002 - T1569.002<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_synology_nas_synology_nas_Malware.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  share-access<br> ↳[nas-share-access-1](Ps/pC_nasshareaccess1.md)<br> ↳[nas-share-access](Ps/pC_nasshareaccess.md)<br> | T1021.002 - Remote Services: SMB/Windows Admin Shares<br>T1087 - Account Discovery<br>T1484 - Group Policy Modification<br> | [<ul><li>5 Rules</li></ul>](RM/r_m_synology_nas_synology_nas_Privilege_Escalation.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                            | Persistence | Privilege Escalation                                                           | Defense Evasion                                                                | Credential Access                                                          | Discovery                                                              | Lateral Movement                                                                                                                                                       | Collection | Command and Control | Exfiltration | Impact |
| -------------- | -------------------------------------------------------------------- | ----------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
|                | [System Services](https://attack.mitre.org/techniques/T1569)<br><br> |             | [Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br> | [Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br> | [Forced Authentication](https://attack.mitre.org/techniques/T1187)<br><br> | [Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)<br><br> |            |                     |              |        |