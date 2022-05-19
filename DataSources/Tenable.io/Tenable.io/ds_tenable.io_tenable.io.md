Vendor: Tenable.io
==================
Product: Tenable.io
-------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   7    |     4      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|     [Cryptomining](../../../UseCases/uc_cryptomining.md)     |  network-connection-failed<br> ↳[tenable-security-alert-1](Ps/pC_tenablesecurityalert1.md)<br> ↳[tenable-security-alert](Ps/pC_tenablesecurityalert.md)<br> | T1496 - Resource Hijacking<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_tenable.io_tenable.io_Cryptomining.md)    |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  network-connection-failed<br> ↳[tenable-security-alert-1](Ps/pC_tenablesecurityalert1.md)<br> ↳[tenable-security-alert](Ps/pC_tenablesecurityalert.md)<br> | T1090.003 - Proxy: Multi-hop Proxy<br>TA0010 - TA0010<br>TA0011 - TA0011<br> | [<ul><li>17 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_tenable.io_tenable.io_Lateral_Movement.md) |
|          [Malware](../../../UseCases/uc_malware.md)          |  network-connection-failed<br> ↳[tenable-security-alert-1](Ps/pC_tenablesecurityalert1.md)<br> ↳[tenable-security-alert](Ps/pC_tenablesecurityalert.md)<br> | TA0011 - TA0011<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_tenable.io_tenable.io_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact                                                                  |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------- |
|                |           |             |                      |                 |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |