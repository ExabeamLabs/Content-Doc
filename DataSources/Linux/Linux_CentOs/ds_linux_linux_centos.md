Vendor: Linux
=============
Product: Linux CentOs
---------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  18   |   7    |         4          |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  network-connection-failed<br> ↳[centos-network-connection-failed](Ps/pC_centosnetworkconnectionfailed.md)<br> | T1090.003 - Proxy: Multi-hop Proxy<br>T1190 - Exploit Public Fasing Application<br>TA0010 - TA0010<br>TA0011 - TA0011<br> | [<ul><li>18 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_linux_linux_centos_Lateral_Movement.md) |
|          [Malware](../../../UseCases/uc_malware.md)          |  network-connection-failed<br> ↳[centos-network-connection-failed](Ps/pC_centosnetworkconnectionfailed.md)<br> | TA0011 - TA0011<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_linux_linux_centos_Malware.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                         | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| -------------------------------------------------------------------------------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           |             |                      |                 |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |