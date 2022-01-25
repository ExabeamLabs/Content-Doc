Vendor: Microsoft
=================
Product: Defender Antivirus
---------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   2    |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  file-alert<br> ↳[raw-defender-av-1116](Ps/pC_rawdefenderav1116.md)<br> | T1003.001 - T1003.001<br>  | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_microsoft_defender_antivirus_Compromised_Credentials.md) |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  file-alert<br> ↳[raw-defender-av-1116](Ps/pC_rawdefenderav1116.md)<br> | T1204 - User Execution<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_microsoft_defender_antivirus_Data_Exfiltration.md)       |
|    [Malware](../../../UseCases/uc_malware.md)    |  file-alert<br> ↳[raw-defender-av-1116](Ps/pC_rawdefenderav1116.md)<br> | T1204 - User Execution<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_microsoft_defender_antivirus_Malware.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  file-alert<br> ↳[raw-defender-av-1116](Ps/pC_rawdefenderav1116.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_microsoft_defender_antivirus_Privilege_Abuse.md)    |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  file-alert<br> ↳[raw-defender-av-1116](Ps/pC_rawdefenderav1116.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_microsoft_defender_antivirus_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                           | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access                                                          | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> |           |                  |            |                     |              |        |