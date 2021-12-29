Vendor: Galaxy
==============
Product: Galaxy
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  10   |   3    |     2      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  physical-access<br> ↳[galaxy-physical-badge-access](Ps/pC_galaxyphysicalbadgeaccess.md)<br><br> print-activity<br> ↳[galaxy-physical-badge-access](Ps/pC_galaxyphysicalbadgeaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_galaxy_galaxy_Abnormal_Authentication_&_Access.md) |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  physical-access<br> ↳[galaxy-physical-badge-access](Ps/pC_galaxyphysicalbadgeaccess.md)<br><br> print-activity<br> ↳[galaxy-physical-badge-access](Ps/pC_galaxyphysicalbadgeaccess.md)<br> | T1052 - Exfiltration Over Physical Medium<br> | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_galaxy_galaxy_Data_Leak.md)    |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  physical-access<br> ↳[galaxy-physical-badge-access](Ps/pC_galaxyphysicalbadgeaccess.md)<br><br> print-activity<br> ↳[galaxy-physical-badge-access](Ps/pC_galaxyphysicalbadgeaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_galaxy_galaxy_Physical_Security.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |