Vendor: HP
==========
Product: Print Server
---------------------
|                          Use-Case                           | Activity Types         | Event Types/Parsers                                                                                                                                                                                                                                           | MITRE TTP         | Content        |
|:-----------------------------------------------------------:| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | -------------- |
| [Lateral Movement](../UseCases/usecase_lateral_movement.md) | - Data Loss Prevention |  print-activity<br> -- [cef-hp-print-activity](../Parsers/parserContent_cef-hp-print-activity.md)<br> -- [hp-print-activity](../Parsers/parserContent_hp-print-activity.md)<br> -- [s-hp-print-activity](../Parsers/parserContent_s-hp-print-activity.md)<br> | T1086 - T1086<br> |  - 1 Rules<br> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilage escalation | Defense evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            |                     |              |        |