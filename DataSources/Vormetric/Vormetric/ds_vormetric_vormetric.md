Vendor: Vormetric
=================
Product: Vormetric
------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  34   |   16   |         5          |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  file-read<br> ↳[vormetric-file-operations](Ps/pC_vormetricfileoperations.md)<br>    | T1003.001 - T1003.001<br>T1003.003 - T1003.003<br>T1083 - File and Directory Discovery<br> | [<ul><li>29 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_vormetric_vormetric_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  file-read<br> ↳[vormetric-file-operations](Ps/pC_vormetricfileoperations.md)<br>    | T1083 - File and Directory Discovery<br>    | [<ul><li>24 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_vormetric_vormetric_Data_Access.md)    |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  file-alert<br> ↳[vormetric-file-operations](Ps/pC_vormetricfileoperations.md)<br>    | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_vormetric_vormetric_Data_Exfiltration.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  file-alert<br> ↳[vormetric-file-operations](Ps/pC_vormetricfileoperations.md)<br>    | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_vormetric_vormetric_Malware.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  file-alert<br> ↳[vormetric-file-operations](Ps/pC_vormetricfileoperations.md)<br><br> file-read<br> ↳[vormetric-file-operations](Ps/pC_vormetricfileoperations.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_vormetric_vormetric_Privilege_Abuse.md)    |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  file-alert<br> ↳[vormetric-file-operations](Ps/pC_vormetricfileoperations.md)<br><br> file-read<br> ↳[vormetric-file-operations](Ps/pC_vormetricfileoperations.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_vormetric_vormetric_Privileged_Activity.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access                                                          | Discovery                                                                         | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  |            |                     |              |        |