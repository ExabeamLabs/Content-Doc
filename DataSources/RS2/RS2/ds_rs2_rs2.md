Vendor: RS2
===========
Product: RS2
------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                     | MITRE TTP                  | Content                                                                                  |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ---------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  failed-physical-access<br> ↳ [rs2-physical-access](Parsers/parserContent_rs2-physical-access.md)<br><br> physical-access<br> ↳ [rs2-physical-access](Parsers/parserContent_rs2-physical-access.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_rs2_rs2_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |