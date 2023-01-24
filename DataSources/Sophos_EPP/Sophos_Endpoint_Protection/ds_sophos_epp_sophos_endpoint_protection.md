Vendor: Sophos EPP
==================
Product: Sophos Endpoint Protection
-----------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  25   |   14   |     3      |      2      |    2    |

|                               Use-Case                               | Event Types/Parsers                                                                                                                                                                                                                                                                 | MITRE TTP                                                                                                                 | Content                                                                                                                               |
|:--------------------------------------------------------------------:| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  dlp-alert<br> ↳ [cef-sophos-dlp-alert-13](Parsers/parserContent_cef-sophos-dlp-alert-13.md)<br><br> usb-insert<br> ↳ [cef-sophos-usb-insert](Parsers/parserContent_cef-sophos-usb-insert.md)<br> ↳ [cef-sophos-usb-insert-1](Parsers/parserContent_cef-sophos-usb-insert-1.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1052 - Exfiltration Over Physical Medium<br>T1204 - User Execution<br> | [<ul><li>21 Rules</li></ul><ul><li>12 Models</li></ul>](Rules_Models/r_m_sophos_epp_sophos_endpoint_protection_Data_Exfiltration.md)  |
|    [Malware Detection](../../../UseCases/uc_malware_detection.md)    |  dlp-alert<br> ↳ [cef-sophos-dlp-alert-13](Parsers/parserContent_cef-sophos-dlp-alert-13.md)<br><br> usb-insert<br> ↳ [cef-sophos-usb-insert](Parsers/parserContent_cef-sophos-usb-insert.md)<br> ↳ [cef-sophos-usb-insert-1](Parsers/parserContent_cef-sophos-usb-insert-1.md)<br> | T1204 - User Execution<br>                                                                                                | [<ul><li>5 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_sophos_epp_sophos_endpoint_protection_Malware_Detection.md)    |
| [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md) |  dlp-alert<br> ↳ [cef-sophos-dlp-alert-13](Parsers/parserContent_cef-sophos-dlp-alert-13.md)<br><br> usb-insert<br> ↳ [cef-sophos-usb-insert](Parsers/parserContent_cef-sophos-usb-insert.md)<br> ↳ [cef-sophos-usb-insert-1](Parsers/parserContent_cef-sophos-usb-insert-1.md)<br> | T1204 - User Execution<br>                                                                                                | [<ul><li>5 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_sophos_epp_sophos_endpoint_protection_Ransomware_Detection.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                                                                                                      | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |