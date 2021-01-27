Vendor: Verdasys Digital Guardian
=================================
Product: Digital Guardian Endpoint Protection
---------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   3    |     1      |      1      |    1    |

|               Use-Case                | Activity Types                         | Event Types/Parsers                                                                                                  | MITRE TTP                                     | Content                                             |
|:-------------------------------------:| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | --------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Data Loss Prevention</li></ul> |  usb-insert<br> ↳ [leef-digitalguardian-usb-insert](../Parsers/parserContent_leef-digitalguardian-usb-insert.md)<br> | T1052 - Exfiltration Over Physical Medium<br> | <ul><li>6 Rules</li></ul><ul><li>3 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |