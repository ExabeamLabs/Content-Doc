Vendor: Skyhigh Networks
========================
Product: Skyhigh Networks CASB
------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   4    |     2      |      1      |    1    |

|                Use-Case                | Activity Types                                                                            | Event Types/Parsers                                                                                                                                                                                                                      | MITRE TTP                                                                    | Content                                                                                                                  |
|:--------------------------------------:| ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| [Other](../../../UseCases/uc_other.md) | <ul><li>Data Loss Prevention</li><li>Endpoint Activity</li><li>Process Activity</li></ul> |  dlp-alert<br> ↳ [skyhigh-dlp-alert-2](Parsers/parserContent_skyhigh-dlp-alert-2.md)<br> ↳ [skyhigh-dlp-alert-1](Parsers/parserContent_skyhigh-dlp-alert-1.md)<br> ↳ [skyhigh-dlp-alert](Parsers/parserContent_skyhigh-dlp-alert.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1204 - User Execution<br> | [<ul><li>19 Rules</li></ul><ul><li>4 Models</li></ul>](Rules_Models/r_m_skyhigh_networks_skyhigh_networks_casb_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------- | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |