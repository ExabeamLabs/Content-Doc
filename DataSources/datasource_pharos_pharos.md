Vendor: Pharos
==============
Product: Pharos
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      1      |    1    |

|                          Use-Case                           | Activity Types                         | Event Types/Parsers                                                                                      | MITRE TTP                                     | Content                   |
|:-----------------------------------------------------------:| -------------------------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------------------------- |
| [Lateral Movement](../UseCases/usecase_lateral_movement.md) | <ul><li>Data Loss Prevention</li></ul> |  print-activity<br> ↳ [s-pharos-print-activity](../Parsers/parserContent_s-pharos-print-activity.md)<br> | T1052 - Exfiltration Over Physical Medium<br> | <ul><li>1 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |