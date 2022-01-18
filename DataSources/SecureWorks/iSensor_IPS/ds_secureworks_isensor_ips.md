Vendor: SecureWorks
===================
Product: iSensor IPS
--------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   7    |     5      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|     [Cryptomining](../../../UseCases/uc_cryptomining.md)     |  network-connection-failed<br> ↳[unix-secureworks-security-alert](Ps/pC_unixsecureworkssecurityalert.md)<br> | T1496 - Resource Hijacking<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_secureworks_isensor_ips_Cryptomining.md)    |
|          [Evasion](../../../UseCases/uc_evasion.md)          |  network-connection-failed<br> ↳[unix-secureworks-security-alert](Ps/pC_unixsecureworkssecurityalert.md)<br> | T1090.003 - Proxy: Multi-hop Proxy<br>T1090.004 - T1090.004<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_secureworks_isensor_ips_Evasion.md)    |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  network-connection-failed<br> ↳[unix-secureworks-security-alert](Ps/pC_unixsecureworkssecurityalert.md)<br> | T1071 - Application Layer Protocol<br>T1090.002 - Proxy: External Proxy<br> | [<ul><li>16 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_secureworks_isensor_ips_Lateral_Movement.md) |
|          [Malware](../../../UseCases/uc_malware.md)          |  network-connection-failed<br> ↳[unix-secureworks-security-alert](Ps/pC_unixsecureworkssecurityalert.md)<br> | T1071 - Application Layer Protocol<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_secureworks_isensor_ips_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                                                                                                    | Exfiltration | Impact                                                                  |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------ | ----------------------------------------------------------------------- |
|                |           |             |                      |                 |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy: External Proxy](https://attack.mitre.org/techniques/T1090/002)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |