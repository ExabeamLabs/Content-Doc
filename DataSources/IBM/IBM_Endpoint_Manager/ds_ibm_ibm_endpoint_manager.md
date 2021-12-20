Vendor: IBM
===========
Product: IBM Endpoint Manager
-----------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   0    |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|     [Cryptomining](../../../UseCases/uc_cryptomining.md)     |  network-connection-failed<br> ↳[s-trusteer-epp-alert](Ps/pC_strusteereppalert.md)<br> | T1496 - Resource Hijacking<br>         | [<ul><li>1 Rules</li></ul>](RM/r_m_ibm_ibm_endpoint_manager_Cryptomining.md)     |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  network-connection-failed<br> ↳[s-trusteer-epp-alert](Ps/pC_strusteereppalert.md)<br> | TA0010 - TA0010<br>TA0011 - TA0011<br> | [<ul><li>6 Rules</li></ul>](RM/r_m_ibm_ibm_endpoint_manager_Lateral_Movement.md) |
|          [Malware](../../../UseCases/uc_malware.md)          |  network-connection-failed<br> ↳[s-trusteer-epp-alert](Ps/pC_strusteereppalert.md)<br> | TA0011 - TA0011<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_ibm_ibm_endpoint_manager_Malware.md)          |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact                                                                  |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ----------------------------------------------------------------------- |
|                |           |             |                      |                 |                   |           |                  |            |                     |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |