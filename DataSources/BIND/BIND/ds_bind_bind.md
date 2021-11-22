Vendor: BIND
============
Product: BIND
-------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  14   |   10   |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  network-alert<br> ↳[bind-dns-query-2](Ps/pC_binddnsquery2.md)<br> ↳[bind-dns-query-4](Ps/pC_binddnsquery4.md)<br> ↳[bind-dns-query-3](Ps/pC_binddnsquery3.md)<br> ↳[bind-dns-query](Ps/pC_binddnsquery.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br> | [<ul><li>8 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_bind_bind_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  network-alert<br> ↳[bind-dns-query-2](Ps/pC_binddnsquery2.md)<br> ↳[bind-dns-query-4](Ps/pC_binddnsquery4.md)<br> ↳[bind-dns-query-3](Ps/pC_binddnsquery3.md)<br> ↳[bind-dns-query](Ps/pC_binddnsquery.md)<br> | T1204 - User Execution<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_bind_bind_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  network-alert<br> ↳[bind-dns-query-2](Ps/pC_binddnsquery2.md)<br> ↳[bind-dns-query-4](Ps/pC_binddnsquery4.md)<br> ↳[bind-dns-query-3](Ps/pC_binddnsquery3.md)<br> ↳[bind-dns-query](Ps/pC_binddnsquery.md)<br> |    | [<ul><li>5 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_bind_bind_Other.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     |              |        |