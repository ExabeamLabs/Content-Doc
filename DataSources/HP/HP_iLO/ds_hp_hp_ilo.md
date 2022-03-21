Vendor: HP
==========
Product: HP iLO
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   6    |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Leak](../../../UseCases/uc_data_leak.md) |  usb-write<br> ↳[hp-ilo-app-login-1](Ps/pC_hpiloapplogin1.md)<br> ↳[hp-ilo-app-login-2](Ps/pC_hpiloapplogin2.md)<br> | T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br>T1091 - Replication Through Removable Media<br> | [<ul><li>15 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_hp_hp_ilo_Data_Leak.md) |
|   [Malware](../../../UseCases/uc_malware.md)   |  usb-write<br> ↳[hp-ilo-app-login-1](Ps/pC_hpiloapplogin1.md)<br> ↳[hp-ilo-app-login-2](Ps/pC_hpiloapplogin2.md)<br> | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_hp_hp_ilo_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                           | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement                                                                         | Collection | Command and Control | Exfiltration                                                                                                                                                                                            | Impact |
| ---------------------------------------------------------------------------------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------------------------------------------------------------------------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091)<br><br> |           |             |                      |                 |                   |           | [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091)<br><br> |            |                     | [Exfiltration Over Physical Medium: Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |