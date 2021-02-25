Vendor: Amag
============
Product: Symmetry Access Control
--------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      1      |    1    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                                                                                                             | MITRE TTP                  | Content                                                                                                                         |
|:--------------------------------------------------------------------------:| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  failed-physical-access<br> ↳ [amag-badge-access](Parsers/parserContent_amag-badge-access.md)<br><br> physical-access<br> ↳ [amag-badge-access](Parsers/parserContent_amag-badge-access.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_amag_symmetry_access_control_Compromised_Credentials.md) |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  failed-physical-access<br> ↳ [amag-badge-access](Parsers/parserContent_amag-badge-access.md)<br><br> physical-access<br> ↳ [amag-badge-access](Parsers/parserContent_amag-badge-access.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_amag_symmetry_access_control_Lateral_Movement.md)                                  |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |