Vendor: Microsoft
=================
Product: Windows Defender
-------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  40   |   20   |     7      |      2      |    2    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | MITRE TTP                                                                                                                                                                                      | Content                                                                                                                        |
|:--------------------------------------------------------------------------:| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  dlp-alert<br> ↳ [s-o365-dlp-alert](Parsers/parserContent_s-o365-dlp-alert.md)<br> ↳ [s-o365-dlp-alert-1](Parsers/parserContent_s-o365-dlp-alert-1.md)<br><br> security-alert<br> ↳ [microsoft-scep-epp-alert](Parsers/parserContent_microsoft-scep-epp-alert.md)<br> ↳ [forefront-epp-cef-alert](Parsers/parserContent_forefront-epp-cef-alert.md)<br> ↳ [raw-scep-epp-alert-csv](Parsers/parserContent_raw-scep-epp-alert-csv.md)<br> ↳ [raw-scep-alert](Parsers/parserContent_raw-scep-alert.md)<br> ↳ [json-microsoft-scep-epp-alert](Parsers/parserContent_json-microsoft-scep-epp-alert.md)<br> ↳ [raw-scep-epp-alert](Parsers/parserContent_raw-scep-epp-alert.md)<br> ↳ [s-scep-epp-alert](Parsers/parserContent_s-scep-epp-alert.md)<br> ↳ [microsoft-scep-security-alert](Parsers/parserContent_microsoft-scep-security-alert.md)<br> ↳ [cef-windows-defender](Parsers/parserContent_cef-windows-defender.md)<br> ↳ [win-def-mal-detect](Parsers/parserContent_win-def-mal-detect.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1059.001 - Command and Scripting Interperter: PowerShell<br>T1078 - Valid Accounts<br>                           | [<ul><li>17 Rules</li></ul><ul><li>9 Models</li></ul>](Rules_Models/r_m_microsoft_windows_defender_Compromised_Credentials.md) |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  dlp-alert<br> ↳ [s-o365-dlp-alert](Parsers/parserContent_s-o365-dlp-alert.md)<br> ↳ [s-o365-dlp-alert-1](Parsers/parserContent_s-o365-dlp-alert-1.md)<br><br> security-alert<br> ↳ [microsoft-scep-epp-alert](Parsers/parserContent_microsoft-scep-epp-alert.md)<br> ↳ [forefront-epp-cef-alert](Parsers/parserContent_forefront-epp-cef-alert.md)<br> ↳ [raw-scep-epp-alert-csv](Parsers/parserContent_raw-scep-epp-alert-csv.md)<br> ↳ [raw-scep-alert](Parsers/parserContent_raw-scep-alert.md)<br> ↳ [json-microsoft-scep-epp-alert](Parsers/parserContent_json-microsoft-scep-epp-alert.md)<br> ↳ [raw-scep-epp-alert](Parsers/parserContent_raw-scep-epp-alert.md)<br> ↳ [s-scep-epp-alert](Parsers/parserContent_s-scep-epp-alert.md)<br> ↳ [microsoft-scep-security-alert](Parsers/parserContent_microsoft-scep-security-alert.md)<br> ↳ [cef-windows-defender](Parsers/parserContent_cef-windows-defender.md)<br> ↳ [win-def-mal-detect](Parsers/parserContent_win-def-mal-detect.md)<br> | T1020 - Automated Exfiltration<br>T1048 - Exfiltration Over Alternative Protocol<br>T1204 - User Execution<br>                                                                                 | [<ul><li>15 Rules</li></ul><ul><li>9 Models</li></ul>](Rules_Models/r_m_microsoft_windows_defender_Data_Exfiltration.md)       |
|       [Malware Detection](../../../UseCases/uc_malware_detection.md)       |  dlp-alert<br> ↳ [s-o365-dlp-alert](Parsers/parserContent_s-o365-dlp-alert.md)<br> ↳ [s-o365-dlp-alert-1](Parsers/parserContent_s-o365-dlp-alert-1.md)<br><br> security-alert<br> ↳ [microsoft-scep-epp-alert](Parsers/parserContent_microsoft-scep-epp-alert.md)<br> ↳ [forefront-epp-cef-alert](Parsers/parserContent_forefront-epp-cef-alert.md)<br> ↳ [raw-scep-epp-alert-csv](Parsers/parserContent_raw-scep-epp-alert-csv.md)<br> ↳ [raw-scep-alert](Parsers/parserContent_raw-scep-alert.md)<br> ↳ [json-microsoft-scep-epp-alert](Parsers/parserContent_json-microsoft-scep-epp-alert.md)<br> ↳ [raw-scep-epp-alert](Parsers/parserContent_raw-scep-epp-alert.md)<br> ↳ [s-scep-epp-alert](Parsers/parserContent_s-scep-epp-alert.md)<br> ↳ [microsoft-scep-security-alert](Parsers/parserContent_microsoft-scep-security-alert.md)<br> ↳ [cef-windows-defender](Parsers/parserContent_cef-windows-defender.md)<br> ↳ [win-def-mal-detect](Parsers/parserContent_win-def-mal-detect.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1059.001 - Command and Scripting Interperter: PowerShell<br>T1078 - Valid Accounts<br>T1204 - User Execution<br> | [<ul><li>11 Rules</li></ul><ul><li>5 Models</li></ul>](Rules_Models/r_m_microsoft_windows_defender_Malware_Detection.md)       |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  dlp-alert<br> ↳ [s-o365-dlp-alert](Parsers/parserContent_s-o365-dlp-alert.md)<br> ↳ [s-o365-dlp-alert-1](Parsers/parserContent_s-o365-dlp-alert-1.md)<br><br> security-alert<br> ↳ [microsoft-scep-epp-alert](Parsers/parserContent_microsoft-scep-epp-alert.md)<br> ↳ [forefront-epp-cef-alert](Parsers/parserContent_forefront-epp-cef-alert.md)<br> ↳ [raw-scep-epp-alert-csv](Parsers/parserContent_raw-scep-epp-alert-csv.md)<br> ↳ [raw-scep-alert](Parsers/parserContent_raw-scep-alert.md)<br> ↳ [json-microsoft-scep-epp-alert](Parsers/parserContent_json-microsoft-scep-epp-alert.md)<br> ↳ [raw-scep-epp-alert](Parsers/parserContent_raw-scep-epp-alert.md)<br> ↳ [s-scep-epp-alert](Parsers/parserContent_s-scep-epp-alert.md)<br> ↳ [microsoft-scep-security-alert](Parsers/parserContent_microsoft-scep-security-alert.md)<br> ↳ [cef-windows-defender](Parsers/parserContent_cef-windows-defender.md)<br> ↳ [win-def-mal-detect](Parsers/parserContent_win-def-mal-detect.md)<br> | T1068 - Exploitation for Privilege Escalation<br>                                                                                                                                              | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_microsoft_windows_defender_Privileged_Activity.md)                                |
|    [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md)    |  dlp-alert<br> ↳ [s-o365-dlp-alert](Parsers/parserContent_s-o365-dlp-alert.md)<br> ↳ [s-o365-dlp-alert-1](Parsers/parserContent_s-o365-dlp-alert-1.md)<br><br> security-alert<br> ↳ [microsoft-scep-epp-alert](Parsers/parserContent_microsoft-scep-epp-alert.md)<br> ↳ [forefront-epp-cef-alert](Parsers/parserContent_forefront-epp-cef-alert.md)<br> ↳ [raw-scep-epp-alert-csv](Parsers/parserContent_raw-scep-epp-alert-csv.md)<br> ↳ [raw-scep-alert](Parsers/parserContent_raw-scep-alert.md)<br> ↳ [json-microsoft-scep-epp-alert](Parsers/parserContent_json-microsoft-scep-epp-alert.md)<br> ↳ [raw-scep-epp-alert](Parsers/parserContent_raw-scep-epp-alert.md)<br> ↳ [s-scep-epp-alert](Parsers/parserContent_s-scep-epp-alert.md)<br> ↳ [microsoft-scep-security-alert](Parsers/parserContent_microsoft-scep-security-alert.md)<br> ↳ [cef-windows-defender](Parsers/parserContent_cef-windows-defender.md)<br> ↳ [win-def-mal-detect](Parsers/parserContent_win-def-mal-detect.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1059.001 - Command and Scripting Interperter: PowerShell<br>T1078 - Valid Accounts<br>T1204 - User Execution<br> | [<ul><li>11 Rules</li></ul><ul><li>5 Models</li></ul>](Rules_Models/r_m_microsoft_windows_defender_Ransomware_Detection.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                                                                                                                                                                                                                       | Persistence                                                         | Privilege Escalation                                                                                                                                          | Defense Evasion                                                                                                                                                                                                                                                               | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                                                                                           | Impact |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Command and Scripting Interperter](https://attack.mitre.org/techniques/T1059)<br><br>[User Execution](https://attack.mitre.org/techniques/T1204)<br><br>[Command and Scripting Interperter: PowerShell](https://attack.mitre.org/techniques/T1059/001)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |