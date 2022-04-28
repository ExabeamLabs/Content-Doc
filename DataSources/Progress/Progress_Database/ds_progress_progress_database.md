Vendor: Progress
================
Product: Progress Database
--------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   3    |     4      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Malware](../../../UseCases/uc_malware.md) |  registry-write<br> ↳[progress-db-remote-logon](Ps/pC_progressdbremotelogon.md)<br> | T1112 - Modify Registry<br>T1547.001 - T1547.001<br>T1574.010 - T1574.010<br>T1574.011 - T1574.011<br> | [<ul><li>6 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_progress_progress_database_Malware.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence                                                                                                                                                      | Privilege Escalation                                                                                                                                             | Defense Evasion                                                                                                                                | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           | [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Modify Registry](https://attack.mitre.org/techniques/T1112)<br><br>[Hijack Execution Flow](https://attack.mitre.org/techniques/T1574)<br><br> |                   |           |                  |            |                     |              |        |