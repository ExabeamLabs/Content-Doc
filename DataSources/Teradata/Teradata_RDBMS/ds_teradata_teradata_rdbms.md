Vendor: Teradata
================
Product: Teradata RDBMS
-----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  31   |   0    |     4      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md) |  database-login<br> ↳[teradata-database-req2](Ps/pC_teradatadatabasereq2.md)<br> ↳[teradata-database-req4](Ps/pC_teradatadatabasereq4.md)<br><br> dlp-alert<br> ↳[teradata-database-req8](Ps/pC_teradatadatabasereq8.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br> | [<ul><li>27 Rules</li></ul>](RM/r_m_teradata_teradata_rdbms_Data_Exfiltration.md) |
|         [Data Leak](../../../UseCases/uc_data_leak.md)         |  database-login<br> ↳[teradata-database-req2](Ps/pC_teradatadatabasereq2.md)<br> ↳[teradata-database-req4](Ps/pC_teradatadatabasereq4.md)<br><br> dlp-alert<br> ↳[teradata-database-req8](Ps/pC_teradatadatabasereq8.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br> | [<ul><li>27 Rules</li></ul>](RM/r_m_teradata_teradata_rdbms_Data_Leak.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  database-login<br> ↳[teradata-database-req2](Ps/pC_teradatadatabasereq2.md)<br> ↳[teradata-database-req4](Ps/pC_teradatadatabasereq4.md)<br><br> dlp-alert<br> ↳[teradata-database-req8](Ps/pC_teradatadatabasereq8.md)<br> | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_teradata_teradata_rdbms_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |