Vendor: Imperva
===============
Product: CounterBreach
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  14   |   8    |     2      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                         | MITRE TTP                                            | Content                                                                                                 |
|:--------------------------------------:| ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  database-alert<br> ↳ [cef-counterbreach-db-alert](Parsers/parserContent_cef-counterbreach-db-alert.md)<br> | T1078 - Valid Accounts<br>T1204 - User Execution<br> | [<ul><li>14 Rules</li></ul><ul><li>8 Models</li></ul>](Rules_Models/r_m_imperva_counterbreach_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                           | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |