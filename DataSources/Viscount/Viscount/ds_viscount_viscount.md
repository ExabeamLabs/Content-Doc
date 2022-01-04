Vendor: Viscount
================
Product: Viscount
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  13   |   5    |     1      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  physical-access<br> ↳[s-viscount-badge-access](Ps/pC_sviscountbadgeaccess.md)<br> ↳[s-viscount-badge-access](Ps/pC_sviscountbadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>5 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_viscount_viscount_Abnormal_Authentication_&_Access.md) |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  physical-access<br> ↳[s-viscount-badge-access](Ps/pC_sviscountbadgeaccess.md)<br> ↳[s-viscount-badge-access](Ps/pC_sviscountbadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>8 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_viscount_viscount_Physical_Security.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  physical-access<br> ↳[s-viscount-badge-access](Ps/pC_sviscountbadgeaccess.md)<br> ↳[s-viscount-badge-access](Ps/pC_sviscountbadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_viscount_viscount_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |