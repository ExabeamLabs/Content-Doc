Vendor: IPTables
================
Product: IPTables
-----------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  56   |   20   |         5          |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  network-connection-failed<br> ↳[iptables-network-connection-failed](Ps/pC_iptablesnetworkconnectionfailed.md)<br><br> network-connection-successful<br> ↳[iptables-network-connection-successful](Ps/pC_iptablesnetworkconnectionsuccessful.md)<br> | T1071 - Application Layer Protocol<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1190 - Exploit Public Fasing Application<br>TA0010 - TA0010<br>TA0011 - TA0011<br> | [<ul><li>56 Rules</li></ul><ul><li>20 Models</li></ul>](RM/r_m_iptables_iptables_Lateral_Movement.md) |
|          [Malware](../../../UseCases/uc_malware.md)          |  network-connection-failed<br> ↳[iptables-network-connection-failed](Ps/pC_iptablesnetworkconnectionfailed.md)<br><br> network-connection-successful<br> ↳[iptables-network-connection-successful](Ps/pC_iptablesnetworkconnectionsuccessful.md)<br> | TA0011 - TA0011<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_iptables_iptables_Malware.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                         | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                      | Exfiltration | Impact |
| -------------------------------------------------------------------------------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------ | ------ |
| [Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           |             |                      |                 |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |