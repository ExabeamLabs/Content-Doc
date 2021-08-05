Vendor: Microsoft
=================
Product: OneDrive
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   8    |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  file-read<br> ↳[cef-onedrive-file-activity](Ps/pC_cefonedrivefileactivity.md)<br> | T1003.003 - T1003.003<br>T1083 - File and Directory Discovery<br>  | [<ul><li>9 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_microsoft_onedrive_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  file-read<br> ↳[cef-onedrive-file-activity](Ps/pC_cefonedrivefileactivity.md)<br> | T1083 - File and Directory Discovery<br>    | [<ul><li>6 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_microsoft_onedrive_Data_Access.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  file-read<br> ↳[cef-onedrive-file-activity](Ps/pC_cefonedrivefileactivity.md)<br> | T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br> | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_microsoft_onedrive_Privilege_Abuse.md)         |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  file-read<br> ↳[cef-onedrive-file-activity](Ps/pC_cefonedrivefileactivity.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_microsoft_onedrive_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access                                                          | Discovery                                                                         | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  |            |                     |              |        |