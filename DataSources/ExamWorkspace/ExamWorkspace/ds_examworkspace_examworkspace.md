Vendor: ExamWorkspace
=====================
Product: ExamWorkspace
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   3    |     2      |      1      |    1    |

|                Use-Case                | Activity Types                                                   | Event Types/Parsers                                                                                  | MITRE TTP                                                          | Content                                                                                                      |
|:--------------------------------------:| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| [Other](../../../UseCases/uc_other.md) | <ul><li>Critical System Activity</li><li>File Activity</li></ul> |  file-read<br> ↳ [s-examworkspace-file-read](Parsers/parserContent_s-examworkspace-file-read.md)<br> | T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br> | [<ul><li>4 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_examworkspace_examworkspace_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery                                                                         | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------------------------------------------------------------------------------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  |            |                     |              |        |