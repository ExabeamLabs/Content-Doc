Vendor: Microsoft
=================
Product: Windows PrintService
-----------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Leak](../../../UseCases/uc_data_leak.md) |  print-activity<br> ↳[syslog-microsoft-print-activity-1](Ps/pC_syslogmicrosoftprintactivity1.md)<br> ↳[s-microsoft-print-activity-1](Ps/pC_smicrosoftprintactivity1.md)<br> ↳[q-microsoft-print-activity](Ps/pC_qmicrosoftprintactivity.md)<br> ↳[s-microsoft-print-activity](Ps/pC_smicrosoftprintactivity.md)<br> ↳[microsoft-print-activity-1](Ps/pC_microsoftprintactivity1.md)<br> ↳[microsoft-print-activity-2](Ps/pC_microsoftprintactivity2.md)<br> ↳[microsoft-print-activity](Ps/pC_microsoftprintactivity.md)<br> ↳[syslog-microsoft-print-activity](Ps/pC_syslogmicrosoftprintactivity.md)<br> ↳[cef-microsoft-print-activity](Ps/pC_cefmicrosoftprintactivity.md)<br> | T1052 - Exfiltration Over Physical Medium<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_microsoft_windows_printservice_Data_Leak.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |