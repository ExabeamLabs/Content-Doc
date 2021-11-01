Vendor: Sailpoint
=================
Product: FAM
------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  33   |   18   |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  file-permission-change<br> ↳[s-sailpoint-fam-file-perimssion-change](Ps/pC_ssailpointfamfileperimssionchange.md)<br> | T1083 - File and Directory Discovery<br>    | [<ul><li>31 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_sailpoint_fam_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  file-permission-change<br> ↳[s-sailpoint-fam-file-perimssion-change](Ps/pC_ssailpointfamfileperimssionchange.md)<br> | T1083 - File and Directory Discovery<br>    | [<ul><li>31 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_sailpoint_fam_Data_Access.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  file-permission-change<br> ↳[s-sailpoint-fam-file-perimssion-change](Ps/pC_ssailpointfamfileperimssionchange.md)<br> | T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br> | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_sailpoint_fam_Privilege_Abuse.md)    |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  file-permission-change<br> ↳[s-sailpoint-fam-file-perimssion-change](Ps/pC_ssailpointfamfileperimssionchange.md)<br> | T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br> | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_sailpoint_fam_Privileged_Activity.md)       |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery                                                                         | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------------------------------------------------------------------------------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  |            |                     |              |        |