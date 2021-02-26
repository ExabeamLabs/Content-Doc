Vendor: IMSS
============
Product: IMSS
-------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  40   |   20   |     6      |      2      |    2    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | MITRE TTP                                                                              | Content                                                                                                       |
|:--------------------------------------------------------------------------:| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  dlp-alert<br> ↳ [imss-dlp-alert](Parsers/parserContent_imss-dlp-alert.md)<br> ↳ [imss-dlp-alert-1](Parsers/parserContent_imss-dlp-alert-1.md)<br><br> security-alert<br> ↳ [imss-security-alert-1](Parsers/parserContent_imss-security-alert-1.md)<br> ↳ [imss-security-alert-2](Parsers/parserContent_imss-security-alert-2.md)<br> ↳ [imss-security-alert-3](Parsers/parserContent_imss-security-alert-3.md)<br> ↳ [imss-security-alert](Parsers/parserContent_imss-security-alert.md)<br> | T1066 - T1066<br>T1078 - Valid Accounts<br>T1086 - T1086<br>                           | [<ul><li>17 Rules</li></ul><ul><li>9 Models</li></ul>](Rules_Models/r_m_imss_imss_Compromised_Credentials.md) |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  dlp-alert<br> ↳ [imss-dlp-alert](Parsers/parserContent_imss-dlp-alert.md)<br> ↳ [imss-dlp-alert-1](Parsers/parserContent_imss-dlp-alert-1.md)<br><br> security-alert<br> ↳ [imss-security-alert-1](Parsers/parserContent_imss-security-alert-1.md)<br> ↳ [imss-security-alert-2](Parsers/parserContent_imss-security-alert-2.md)<br> ↳ [imss-security-alert-3](Parsers/parserContent_imss-security-alert-3.md)<br> ↳ [imss-security-alert](Parsers/parserContent_imss-security-alert.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1204 - User Execution<br>           | [<ul><li>15 Rules</li></ul><ul><li>9 Models</li></ul>](Rules_Models/r_m_imss_imss_Data_Exfiltration.md)       |
|       [Malware Detection](../../../UseCases/uc_malware_detection.md)       |  dlp-alert<br> ↳ [imss-dlp-alert](Parsers/parserContent_imss-dlp-alert.md)<br> ↳ [imss-dlp-alert-1](Parsers/parserContent_imss-dlp-alert-1.md)<br><br> security-alert<br> ↳ [imss-security-alert-1](Parsers/parserContent_imss-security-alert-1.md)<br> ↳ [imss-security-alert-2](Parsers/parserContent_imss-security-alert-2.md)<br> ↳ [imss-security-alert-3](Parsers/parserContent_imss-security-alert-3.md)<br> ↳ [imss-security-alert](Parsers/parserContent_imss-security-alert.md)<br> | T1066 - T1066<br>T1078 - Valid Accounts<br>T1086 - T1086<br>T1204 - User Execution<br> | [<ul><li>11 Rules</li></ul><ul><li>5 Models</li></ul>](Rules_Models/r_m_imss_imss_Malware_Detection.md)       |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  dlp-alert<br> ↳ [imss-dlp-alert](Parsers/parserContent_imss-dlp-alert.md)<br> ↳ [imss-dlp-alert-1](Parsers/parserContent_imss-dlp-alert-1.md)<br><br> security-alert<br> ↳ [imss-security-alert-1](Parsers/parserContent_imss-security-alert-1.md)<br> ↳ [imss-security-alert-2](Parsers/parserContent_imss-security-alert-2.md)<br> ↳ [imss-security-alert-3](Parsers/parserContent_imss-security-alert-3.md)<br> ↳ [imss-security-alert](Parsers/parserContent_imss-security-alert.md)<br> | T1068 - Exploitation for Privilege Escalation<br>                                      | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_imss_imss_Privileged_Activity.md)                                |
|    [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md)    |  dlp-alert<br> ↳ [imss-dlp-alert](Parsers/parserContent_imss-dlp-alert.md)<br> ↳ [imss-dlp-alert-1](Parsers/parserContent_imss-dlp-alert-1.md)<br><br> security-alert<br> ↳ [imss-security-alert-1](Parsers/parserContent_imss-security-alert-1.md)<br> ↳ [imss-security-alert-2](Parsers/parserContent_imss-security-alert-2.md)<br> ↳ [imss-security-alert-3](Parsers/parserContent_imss-security-alert-3.md)<br> ↳ [imss-security-alert](Parsers/parserContent_imss-security-alert.md)<br> | T1066 - T1066<br>T1078 - Valid Accounts<br>T1086 - T1086<br>T1204 - User Execution<br> | [<ul><li>11 Rules</li></ul><ul><li>5 Models</li></ul>](Rules_Models/r_m_imss_imss_Ransomware_Detection.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                           | Persistence                                                         | Privilege Escalation                                                                                                                                          | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                | Impact |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------- | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |