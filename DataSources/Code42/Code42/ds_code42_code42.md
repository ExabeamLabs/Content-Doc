Vendor: Code42
==============
Product: Code42
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   2    |     2      |      3      |    3    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                                                                                                   | MITRE TTP                                            | Content                                                                                        |
|:--------------------------------------:| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  file-delete<br> ↳ [code42-file-operations](Parsers/parserContent_code42-file-operations.md)<br><br> file-read<br> ↳ [code42-file-operations](Parsers/parserContent_code42-file-operations.md)<br><br> file-write<br> ↳ [code42-file-operations](Parsers/parserContent_code42-file-operations.md)<br> | T1078 - Valid Accounts<br>T1204 - User Execution<br> | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](Rules_Models/r_m_code42_code42_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                           | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |