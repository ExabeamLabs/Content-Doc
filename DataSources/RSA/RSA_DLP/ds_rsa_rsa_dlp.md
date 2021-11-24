Vendor: RSA
===========
Product: RSA DLP
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  35   |   19   |     4      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md) |  dlp-alert<br> ↳[rsa-dlp-alert](Ps/pC_rsadlpalert.md)<br> ↳[rsa-dlp-email-alert](Ps/pC_rsadlpemailalert.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br> | [<ul><li>31 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_rsa_rsa_dlp_Data_Exfiltration.md) |
|         [Data Leak](../../../UseCases/uc_data_leak.md)         |  dlp-alert<br> ↳[rsa-dlp-alert](Ps/pC_rsadlpalert.md)<br> ↳[rsa-dlp-email-alert](Ps/pC_rsadlpemailalert.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br> | [<ul><li>31 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_rsa_rsa_dlp_Data_Leak.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-alert<br> ↳[rsa-dlp-alert](Ps/pC_rsadlpalert.md)<br> ↳[rsa-dlp-email-alert](Ps/pC_rsadlpemailalert.md)<br> | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_rsa_rsa_dlp_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  dlp-alert<br> ↳[rsa-dlp-alert](Ps/pC_rsadlpalert.md)<br> ↳[rsa-dlp-email-alert](Ps/pC_rsadlpemailalert.md)<br> |    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_rsa_rsa_dlp_Other.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |