Vendor: Mvision
===============
Product: Mvision
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  33   |   20   |     4      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md) |  dlp-alert<br> ↳[s-mvision-dlp-alert](Ps/pC_smvisiondlpalert.md)<br> ↳[s-mvision-dlp-alert-1](Ps/pC_smvisiondlpalert1.md)<br> ↳[s-mvision-dlp-alert-3](Ps/pC_smvisiondlpalert3.md)<br> ↳[s-mvision-dlp-alert-2](Ps/pC_smvisiondlpalert2.md)<br> ↳[s-mvision-dlp-alert-5](Ps/pC_smvisiondlpalert5.md)<br> ↳[s-mvision-dlp-alert-4](Ps/pC_smvisiondlpalert4.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br> | [<ul><li>29 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_mvision_mvision_Data_Exfiltration.md) |
|         [Data Leak](../../../UseCases/uc_data_leak.md)         |  dlp-alert<br> ↳[s-mvision-dlp-alert](Ps/pC_smvisiondlpalert.md)<br> ↳[s-mvision-dlp-alert-1](Ps/pC_smvisiondlpalert1.md)<br> ↳[s-mvision-dlp-alert-3](Ps/pC_smvisiondlpalert3.md)<br> ↳[s-mvision-dlp-alert-2](Ps/pC_smvisiondlpalert2.md)<br> ↳[s-mvision-dlp-alert-5](Ps/pC_smvisiondlpalert5.md)<br> ↳[s-mvision-dlp-alert-4](Ps/pC_smvisiondlpalert4.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br> | [<ul><li>29 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_mvision_mvision_Data_Leak.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-alert<br> ↳[s-mvision-dlp-alert](Ps/pC_smvisiondlpalert.md)<br> ↳[s-mvision-dlp-alert-1](Ps/pC_smvisiondlpalert1.md)<br> ↳[s-mvision-dlp-alert-3](Ps/pC_smvisiondlpalert3.md)<br> ↳[s-mvision-dlp-alert-2](Ps/pC_smvisiondlpalert2.md)<br> ↳[s-mvision-dlp-alert-5](Ps/pC_smvisiondlpalert5.md)<br> ↳[s-mvision-dlp-alert-4](Ps/pC_smvisiondlpalert4.md)<br> | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_mvision_mvision_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |