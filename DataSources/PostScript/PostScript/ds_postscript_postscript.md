Vendor: PostScript
==================
Product: PostScript
-------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      1      |    1    |

|                                Use-Case                                | Event Types/Parsers                                                                                               | MITRE TTP                                     | Content                                                                                      |
|:----------------------------------------------------------------------:| ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [Data Leak via Printer](../../../UseCases/uc_data_leak_via_printer.md) |  print-activity<br> ↳ [cef-postscript-print-activity](Parsers/parserContent_cef-postscript-print-activity.md)<br> | T1052 - Exfiltration Over Physical Medium<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_postscript_postscript_Data_Leak_via_Printer.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |