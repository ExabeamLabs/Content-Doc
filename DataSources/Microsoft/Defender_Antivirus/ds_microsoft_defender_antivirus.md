Vendor: Microsoft
=================
Product: Defender Antivirus
---------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   2    |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|   [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)   |  file-alert<br> ↳[raw-defender-av-1116](Ps/pC_rawdefenderav1116.md)<br> | TA0002 - TA0002<br>        | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_microsoft_defender_antivirus_Data_Exfiltration.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  file-alert<br> ↳[raw-defender-av-1116](Ps/pC_rawdefenderav1116.md)<br> | TA0002 - TA0002<br>        | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_microsoft_defender_antivirus_Malware.md)    |
|     [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)     |  file-alert<br> ↳[raw-defender-av-1116](Ps/pC_rawdefenderav1116.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_microsoft_defender_antivirus_Privilege_Abuse.md)    |
| [Privileged Activity](../../../UseCases/uc_privileged_activity.md) |  file-alert<br> ↳[raw-defender-av-1116](Ps/pC_rawdefenderav1116.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_microsoft_defender_antivirus_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |