Vendor: Cylance
===============
Product: Cylance
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   9    |     4      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                     | MITRE TTP                                                                                                              | Content                                                                                           |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  security-alert<br> ↳ [cylance-security-alert-1](Parsers/parserContent_cylance-security-alert-1.md)<br> | T1066 - T1066<br>T1068 - Exploitation for Privilege Escalation<br>T1078 - Valid Accounts<br>T1204 - User Execution<br> | [<ul><li>18 Rules</li></ul><ul><li>9 Models</li></ul>](Rules_Models/r_m_cylance_cylance_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                           | Persistence                                                         | Privilege Escalation                                                                                                                                          | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |