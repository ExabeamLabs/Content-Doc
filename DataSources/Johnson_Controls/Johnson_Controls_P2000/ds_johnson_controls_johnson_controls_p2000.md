Vendor: Johnson Controls
========================
Product: Johnson Controls P2000
-------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      1      |    1    |

|                                           Use-Case                                           | Event Types/Parsers                                                                                            | MITRE TTP                  | Content                                                                                                                                             |
|:--------------------------------------------------------------------------------------------:| -------------------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  physical-access<br> ↳ [p2000-physical-badge-access](Parsers/parserContent_p2000-physical-badge-access.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_johnson_controls_johnson_controls_p2000_Abnormal_Authentication_&_Access.md) |
|         [Access to Physical Space](../../../UseCases/uc_access_to_physical_space.md)         |  physical-access<br> ↳ [p2000-physical-badge-access](Parsers/parserContent_p2000-physical-badge-access.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_johnson_controls_johnson_controls_p2000_Access_to_Physical_Space.md)                                   |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |