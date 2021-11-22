Vendor: Qualys
==============
Product: Qualys
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  15   |   9    |     7      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|     [Cryptomining](../../../UseCases/uc_cryptomining.md)     |  network-connection-failed<br> ↳[qualys-security-alert](Ps/pC_qualyssecurityalert.md)<br> | T1496 - Resource Hijacking<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_qualys_qualys_Cryptomining.md)    |
|          [Evasion](../../../UseCases/uc_evasion.md)          |  network-connection-failed<br> ↳[qualys-security-alert](Ps/pC_qualyssecurityalert.md)<br> | T1090.003 - Proxy: Multi-hop Proxy<br>T1090.004 - T1090.004<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_qualys_qualys_Evasion.md)    |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  network-connection-failed<br> ↳[qualys-security-alert](Ps/pC_qualyssecurityalert.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br>T1090.002 - Proxy: External Proxy<br>T1571 - Non-Standard Port<br> | [<ul><li>8 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_qualys_qualys_Lateral_Movement.md) |
|          [Malware](../../../UseCases/uc_malware.md)          |  network-connection-failed<br> ↳[qualys-security-alert](Ps/pC_qualyssecurityalert.md)<br> | T1071 - Application Layer Protocol<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_qualys_qualys_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  network-connection-failed<br> ↳[qualys-security-alert](Ps/pC_qualyssecurityalert.md)<br> |    | [<ul><li>6 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_qualys_qualys_Other.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                                                                                                                                                                          | Exfiltration                                                                                | Impact                                                                  |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
|                |           |             |                      |                 |                   |           |                  |            | [Non-Standard Port](https://attack.mitre.org/techniques/T1571)<br><br>[Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy: External Proxy](https://attack.mitre.org/techniques/T1090/002)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |