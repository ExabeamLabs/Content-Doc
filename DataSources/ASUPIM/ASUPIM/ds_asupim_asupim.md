Vendor: ASUPIM
==============
Product: ASUPIM
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      1      |    1    |

|                           Use-Case                           | Event Types/Parsers                                                                                 | MITRE TTP                                     | Content                                                                         |
|:------------------------------------------------------------:| --------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------- |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  print-activity<br> ↳ [cef-asupim-print-event](Parsers/parserContent_cef-asupim-print-event.md)<br> | T1052 - Exfiltration Over Physical Medium<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_asupim_asupim_Lateral_Movement.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |