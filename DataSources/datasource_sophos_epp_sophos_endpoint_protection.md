Vendor: Sophos EPP
==================
Product: Sophos Endpoint Protection
-----------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   3    |     1      |      1      |    1    |

|               Use-Case                | Activity Types                         | Event Types/Parsers                                                                                                                                                                   | MITRE TTP                                     | Content                                             |
|:-------------------------------------:| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | --------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Data Loss Prevention</li></ul> |  usb-insert<br> ↳ [cef-sophos-usb-insert](../Parsers/parserContent_cef-sophos-usb-insert.md)<br> ↳ [cef-sophos-usb-insert-1](../Parsers/parserContent_cef-sophos-usb-insert-1.md)<br> | T1052 - Exfiltration Over Physical Medium<br> | <ul><li>6 Rules</li></ul><ul><li>3 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |