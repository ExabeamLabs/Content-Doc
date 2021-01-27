Vendor: Imperva
===============
Product: CounterBreach
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   5    |     2      |      1      |    1    |

|                                 Use-Case                                  | Activity Types                                             | Event Types/Parsers                                                                                            | MITRE TTP                  | Content                                              |
|:-------------------------------------------------------------------------:| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------- | ---------------------------------------------------- |
| [Compromised Credentials](../UseCases/usecase_compromised_credentials.md) | <ul><li>Database Activity</li><li>Database Alert</li></ul> |  database-alert<br> ↳ [cef-counterbreach-db-alert](../Parsers/parserContent_cef-counterbreach-db-alert.md)<br> | T1078 - Valid Accounts<br> | <ul><li>16 Rules</li></ul><ul><li>5 Models</li></ul> |
|       [Malware Detection](../UseCases/usecase_malware_detection.md)       | <ul><li>Endpoint Activity</li></ul>                        |  database-alert<br> ↳ [cef-counterbreach-db-alert](../Parsers/parserContent_cef-counterbreach-db-alert.md)<br> | T1204 - User Execution<br> | <ul><li>2 Rules</li></ul>                            |
|    [Ransomware Detection](../UseCases/usecase_ransomware_detection.md)    | <ul><li>Endpoint Activity</li></ul>                        |  database-alert<br> ↳ [cef-counterbreach-db-alert](../Parsers/parserContent_cef-counterbreach-db-alert.md)<br> | T1204 - User Execution<br> | <ul><li>2 Rules</li></ul>                            |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                           | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |