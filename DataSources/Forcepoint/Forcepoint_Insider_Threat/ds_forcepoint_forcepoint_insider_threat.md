Vendor: Forcepoint
==================
Product: Forcepoint Insider Threat
----------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   11   |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md) |  dlp-alert<br> ↳[cef-forcepoint-it-dlp-alert](Ps/pC_cefforcepointitdlpalert.md)<br> | T1020 - Automated Exfiltration<br>T1048 - Exfiltration Over Alternative Protocol<br>T1204 - User Execution<br> | [<ul><li>15 Rules</li></ul><ul><li>9 Models</li></ul>](RM/r_m_forcepoint_forcepoint_insider_threat_Data_Exfiltration.md) |
|         [Data Leak](../../../UseCases/uc_data_leak.md)         |  dlp-alert<br> ↳[cef-forcepoint-it-dlp-alert](Ps/pC_cefforcepointitdlpalert.md)<br> | T1020 - Automated Exfiltration<br>T1048 - Exfiltration Over Alternative Protocol<br>T1204 - User Execution<br> | [<ul><li>15 Rules</li></ul><ul><li>9 Models</li></ul>](RM/r_m_forcepoint_forcepoint_insider_threat_Data_Leak.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-alert<br> ↳[cef-forcepoint-it-dlp-alert](Ps/pC_cefforcepointitdlpalert.md)<br> | T1204 - User Execution<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_forcepoint_forcepoint_insider_threat_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                                                                                           | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |