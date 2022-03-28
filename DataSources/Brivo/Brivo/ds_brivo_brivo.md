Vendor: Brivo
=============
Product: Brivo
--------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  10   |   5    |     1      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  database-delete<br> ↳[brivo-badge-access](Ps/pC_brivobadgeaccess.md)<br><br> physical-access<br> ↳[brivo-badge-access](Ps/pC_brivobadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_brivo_brivo_Abnormal_Authentication_&_Access.md) |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  database-delete<br> ↳[brivo-badge-access](Ps/pC_brivobadgeaccess.md)<br><br> physical-access<br> ↳[brivo-badge-access](Ps/pC_brivobadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>7 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_brivo_brivo_Physical_Security.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  database-delete<br> ↳[brivo-badge-access](Ps/pC_brivobadgeaccess.md)<br><br> physical-access<br> ↳[brivo-badge-access](Ps/pC_brivobadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_brivo_brivo_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |