Vendor: EndPoint
================
Product: EndPoint
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   11   |     3      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                        | MITRE TTP                                                                                                      | Content                                                                                              |
|:--------------------------------------:| ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  dlp-alert<br> ↳ [s-endpoint-dlp-alert](Parsers/parserContent_s-endpoint-dlp-alert.md)<br> | T1020 - Automated Exfiltration<br>T1048 - Exfiltration Over Alternative Protocol<br>T1204 - User Execution<br> | [<ul><li>19 Rules</li></ul><ul><li>11 Models</li></ul>](Rules_Models/r_m_endpoint_endpoint_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                                                                                           | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |