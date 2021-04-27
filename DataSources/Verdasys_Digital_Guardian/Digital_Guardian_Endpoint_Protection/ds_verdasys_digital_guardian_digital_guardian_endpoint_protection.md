Vendor: Verdasys Digital Guardian
=================================
Product: Digital Guardian Endpoint Protection
---------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   3    |     1      |      1      |    1    |

|                            Use-Case                            | Event Types/Parsers                                                                                               | MITRE TTP                                                                | Content                                                                                                                                                     |
|:--------------------------------------------------------------:| ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md) |  usb-insert<br> ↳ [leef-digitalguardian-usb-insert](Parsers/parserContent_leef-digitalguardian-usb-insert.md)<br> | T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br> | [<ul><li>6 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_verdasys_digital_guardian_digital_guardian_endpoint_protection_Data_Exfiltration.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                                                                                                                            | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Physical Medium: Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |