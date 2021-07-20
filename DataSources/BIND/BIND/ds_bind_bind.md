Vendor: BIND
============
Product: BIND
-------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Malware](../../../UseCases/uc_malware.md) |  dns-query<br> ↳[bind-dns-query-2](Ps/pC_binddnsquery2.md)<br> ↳[bind-dns-query-4](Ps/pC_binddnsquery4.md)<br> ↳[bind-dns-query-3](Ps/pC_binddnsquery3.md)<br> ↳[bind-dns-query](Ps/pC_binddnsquery.md)<br> | T1071.004 - Application Layer Protocol: DNS<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>2 Rules</li></ul>](RM/r_m_bind_bind_Malware.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                                                                                                                                                     | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004)<br><br>[Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |