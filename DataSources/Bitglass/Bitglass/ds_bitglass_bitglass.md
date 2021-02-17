Vendor: Bitglass
================
Product: Bitglass
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   4    |     2      |      1      |    1    |

|                               Use-Case                               | Activity Types                                                                            | Event Types/Parsers                                                                            | MITRE TTP                                                                    | Content                                                                                                           |
|:--------------------------------------------------------------------:| ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    | <ul><li>Data Loss Prevention</li></ul>                                                    |  dlp-alert<br> ↳ [cef-bitglass-dlp-alert](Parsers/parserContent_cef-bitglass-dlp-alert.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1204 - User Execution<br> | [<ul><li>15 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_bitglass_bitglass_Data_Exfiltration.md)   |
|    [Malware Detection](../../../UseCases/uc_malware_detection.md)    | <ul><li>Data Loss Prevention</li><li>Endpoint Activity</li><li>Process Activity</li></ul> |  dlp-alert<br> ↳ [cef-bitglass-dlp-alert](Parsers/parserContent_cef-bitglass-dlp-alert.md)<br> | T1204 - User Execution<br>                                                   | [<ul><li>5 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_bitglass_bitglass_Malware_Detection.md)    |
| [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md) | <ul><li>Data Loss Prevention</li><li>Endpoint Activity</li><li>Process Activity</li></ul> |  dlp-alert<br> ↳ [cef-bitglass-dlp-alert](Parsers/parserContent_cef-bitglass-dlp-alert.md)<br> | T1204 - User Execution<br>                                                   | [<ul><li>5 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_bitglass_bitglass_Ransomware_Detection.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------- | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |