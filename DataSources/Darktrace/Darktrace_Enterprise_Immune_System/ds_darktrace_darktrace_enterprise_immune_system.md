Vendor: Darktrace
=================
Product: Darktrace Enterprise Immune System
-------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  35   |   19   |     4      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md) |  dlp-alert<br> ↳[darktrace-alert-1](Ps/pC_darktracealert1.md)<br> ↳[cef-darktrace](Ps/pC_cefdarktrace.md)<br> | T1020 - Automated Exfiltration<br>T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br>T1204 - User Execution<br> | [<ul><li>31 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_darktrace_darktrace_enterprise_immune_system_Data_Exfiltration.md) |
|         [Data Leak](../../../UseCases/uc_data_leak.md)         |  dlp-alert<br> ↳[darktrace-alert-1](Ps/pC_darktracealert1.md)<br> ↳[cef-darktrace](Ps/pC_cefdarktrace.md)<br> | T1020 - Automated Exfiltration<br>T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br>T1204 - User Execution<br> | [<ul><li>31 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_darktrace_darktrace_enterprise_immune_system_Data_Leak.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-alert<br> ↳[darktrace-alert-1](Ps/pC_darktracealert1.md)<br> ↳[cef-darktrace](Ps/pC_cefdarktrace.md)<br> | T1204 - User Execution<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_darktrace_darktrace_enterprise_immune_system_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  dlp-alert<br> ↳[darktrace-alert-1](Ps/pC_darktracealert1.md)<br> ↳[cef-darktrace](Ps/pC_cefdarktrace.md)<br> |    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_darktrace_darktrace_enterprise_immune_system_Other.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                                                                                                           | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |