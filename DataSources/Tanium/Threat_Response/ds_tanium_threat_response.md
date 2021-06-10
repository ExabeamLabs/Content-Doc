Vendor: Tanium
==============
Product: Threat Response
------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  21   |   11   |     3      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                            | MITRE TTP                                                                                                                                | Content                                                                                                   |
|:--------------------------------------:| ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  process-alert<br> ↳ [tanium-process-alert](Parsers/parserContent_tanium-process-alert.md)<br> | T1003 - OS Credential Dumping<br>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1204 - User Execution<br> | [<ul><li>21 Rules</li></ul><ul><li>11 Models</li></ul>](Rules_Models/r_m_tanium_threat_response_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access                                                          | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> |           |                  |            |                     |              |        |