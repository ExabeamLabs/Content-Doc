Vendor: Gallagher
=================
Product: Access Control
-----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  12   |   6    |     1      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  failed-physical-access<br> ↳[gallagher-failed-physical-access](Ps/pC_gallagherfailedphysicalaccess.md)<br><br> physical-access<br> ↳[gallagher-physical-access](Ps/pC_gallagherphysicalaccess.md)<br> ↳[gallagher-physical-access-1](Ps/pC_gallagherphysicalaccess1.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_gallagher_access_control_Abnormal_Authentication_&_Access.md) |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  failed-physical-access<br> ↳[gallagher-failed-physical-access](Ps/pC_gallagherfailedphysicalaccess.md)<br><br> physical-access<br> ↳[gallagher-physical-access](Ps/pC_gallagherphysicalaccess.md)<br> ↳[gallagher-physical-access-1](Ps/pC_gallagherphysicalaccess1.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>9 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_gallagher_access_control_Physical_Security.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  failed-physical-access<br> ↳[gallagher-failed-physical-access](Ps/pC_gallagherfailedphysicalaccess.md)<br><br> physical-access<br> ↳[gallagher-physical-access](Ps/pC_gallagherphysicalaccess.md)<br> ↳[gallagher-physical-access-1](Ps/pC_gallagherphysicalaccess1.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_gallagher_access_control_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |