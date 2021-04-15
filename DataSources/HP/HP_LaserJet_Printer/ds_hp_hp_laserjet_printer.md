Vendor: HP
==========
Product: HP LaserJet Printer
----------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      1      |    1    |

|                           Use-Case                           | Event Types/Parsers                                                                       | MITRE TTP                                     | Content                                                                                  |
|:------------------------------------------------------------:| ----------------------------------------------------------------------------------------- | --------------------------------------------- | ---------------------------------------------------------------------------------------- |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  print-activity<br> ↳ [gm-print-activity](Parsers/parserContent_gm-print-activity.md)<br> | T1052 - Exfiltration Over Physical Medium<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_hp_hp_laserjet_printer_Lateral_Movement.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |