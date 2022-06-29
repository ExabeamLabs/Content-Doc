Vendor: Trend Micro
===================
Product: Trend Micro
--------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  56   |   20   |     5      |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  database-failed-login<br> ↳[cef-trendmicro-database-failed-login](Ps/pC_ceftrendmicrodatabasefailedlogin.md)<br><br> network-connection-failed<br> ↳[trendmicro-network-connection](Ps/pC_trendmicronetworkconnection.md)<br><br> network-connection-successful<br> ↳[trendmicro-network-connection](Ps/pC_trendmicronetworkconnection.md)<br> | T1071 - Application Layer Protocol<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1190 - Exploit Public Fasing Application<br>TA0010 - TA0010<br>TA0011 - TA0011<br> | [<ul><li>56 Rules</li></ul><ul><li>20 Models</li></ul>](RM/r_m_trend_micro_trend_micro_Lateral_Movement.md) |
|          [Malware](../../../UseCases/uc_malware.md)          |  database-failed-login<br> ↳[cef-trendmicro-database-failed-login](Ps/pC_ceftrendmicrodatabasefailedlogin.md)<br><br> network-connection-failed<br> ↳[trendmicro-network-connection](Ps/pC_trendmicronetworkconnection.md)<br><br> network-connection-successful<br> ↳[trendmicro-network-connection](Ps/pC_trendmicronetworkconnection.md)<br> | TA0011 - TA0011<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_trend_micro_trend_micro_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                         | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                      | Exfiltration | Impact |
| -------------------------------------------------------------------------------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------ | ------ |
| [Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           |             |                      |                 |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |