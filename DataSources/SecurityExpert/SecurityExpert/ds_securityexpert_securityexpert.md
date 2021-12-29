Vendor: SecurityExpert
======================
Product: SecurityExpert
-----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  13   |   10   |     5      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|     [Cryptomining](../../../UseCases/uc_cryptomining.md)     |  network-connection-successful<br> ↳[securityexpert-badge-access](Ps/pC_securityexpertbadgeaccess.md)<br> | T1496 - Resource Hijacking<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_securityexpert_securityexpert_Cryptomining.md)    |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  network-connection-successful<br> ↳[securityexpert-badge-access](Ps/pC_securityexpertbadgeaccess.md)<br> | T1071 - Application Layer Protocol<br>T1190 - Exploit Public Fasing Application<br>TA0010 - TA0010<br>TA0011 - TA0011<br> | [<ul><li>12 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_securityexpert_securityexpert_Lateral_Movement.md) |
|          [Malware](../../../UseCases/uc_malware.md)          |  network-connection-successful<br> ↳[securityexpert-badge-access](Ps/pC_securityexpertbadgeaccess.md)<br> | TA0011 - TA0011<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_securityexpert_securityexpert_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                         | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact                                                                  |
| -------------------------------------------------------------------------------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------- |
| [Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |