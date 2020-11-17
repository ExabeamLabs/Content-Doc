Vendor: ASUPIM
==============
Product: ASUPIM
---------------
|                          Use-Case                           | Activity Types         | Event Types/Parsers                                                                                     | MITRE TTP                                     | Content        |
|:-----------------------------------------------------------:| ---------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------- | -------------- |
| [Lateral Movement](../UseCases/usecase_lateral_movement.md) | - Data Loss Prevention |  print-activity<br> -- [cef-asupim-print-event](../Parsers/parserContent_cef-asupim-print-event.md)<br> | T1052 - Exfiltration Over Physical Medium<br> |  - 1 Rules<br> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilage escalation | Defense evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |