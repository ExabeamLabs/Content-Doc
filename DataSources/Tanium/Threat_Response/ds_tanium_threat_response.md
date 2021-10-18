Vendor: Tanium
==============
Product: Threat Response
------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  24   |   11   |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  process-alert<br> ↳[tanium-process-alert](Ps/pC_taniumprocessalert.md)<br> | T1003 - OS Credential Dumping<br>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1204 - User Execution<br> | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_tanium_threat_response_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  process-alert<br> ↳[tanium-process-alert](Ps/pC_taniumprocessalert.md)<br> | T1204 - User Execution<br>    | [<ul><li>18 Rules</li></ul><ul><li>9 Models</li></ul>](RM/r_m_tanium_threat_response_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  process-alert<br> ↳[tanium-process-alert](Ps/pC_taniumprocessalert.md)<br> |    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_tanium_threat_response_Other.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access                                                          | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> |           |                  |            |                     |              |        |