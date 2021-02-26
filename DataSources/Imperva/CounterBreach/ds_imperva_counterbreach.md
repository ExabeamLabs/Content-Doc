Vendor: Imperva
===============
Product: CounterBreach
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   11   |     2      |      1      |    1    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                         | MITRE TTP                  | Content                                                                                                                    |
|:--------------------------------------------------------------------------:| ----------------------------------------------------------------------------------------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-alert<br> ↳ [cef-counterbreach-db-alert](Parsers/parserContent_cef-counterbreach-db-alert.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>17 Rules</li></ul><ul><li>10 Models</li></ul>](Rules_Models/r_m_imperva_counterbreach_Compromised_Credentials.md) |
|       [Malware Detection](../../../UseCases/uc_malware_detection.md)       |  database-alert<br> ↳ [cef-counterbreach-db-alert](Parsers/parserContent_cef-counterbreach-db-alert.md)<br> | T1204 - User Execution<br> | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_imperva_counterbreach_Malware_Detection.md)         |
|    [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md)    |  database-alert<br> ↳ [cef-counterbreach-db-alert](Parsers/parserContent_cef-counterbreach-db-alert.md)<br> | T1204 - User Execution<br> | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_imperva_counterbreach_Ransomware_Detection.md)      |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                           | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |