Vendor: Microsoft Windows
=========================
Product: Microsoft Windows
--------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      1      |    1    |

|                Use-Case                | Activity Types                             | Event Types/Parsers                                            | MITRE TTP                         | Content                                                                                                              |
|:--------------------------------------:| ------------------------------------------ | -------------------------------------------------------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) | <ul><li>Critical System Activity</li></ul> |  ds-access<br> ↳ [q-4662](Parsers/parserContent_q-4662.md)<br> | T1003 - OS Credential Dumping<br> | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_microsoft_windows_microsoft_windows_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access                                                          | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | -------------------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> |           |                  |            |                     |              |        |