Vendor: Paxton
==============
Product: NET2DOOR
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  12   |   6    |     1      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  failed-physical-access<br> ↳[paxton-badge-access](Ps/pC_paxtonbadgeaccess.md)<br> ↳[s-net2door-badge-access](Ps/pC_snet2doorbadgeaccess.md)<br><br> physical-access<br> ↳[paxton-badge-access](Ps/pC_paxtonbadgeaccess.md)<br> ↳[s-net2door-badge-access](Ps/pC_snet2doorbadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_paxton_net2door_Abnormal_Authentication_&_Access.md) |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  failed-physical-access<br> ↳[paxton-badge-access](Ps/pC_paxtonbadgeaccess.md)<br> ↳[s-net2door-badge-access](Ps/pC_snet2doorbadgeaccess.md)<br><br> physical-access<br> ↳[paxton-badge-access](Ps/pC_paxtonbadgeaccess.md)<br> ↳[s-net2door-badge-access](Ps/pC_snet2doorbadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>9 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_paxton_net2door_Physical_Security.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  failed-physical-access<br> ↳[paxton-badge-access](Ps/pC_paxtonbadgeaccess.md)<br> ↳[s-net2door-badge-access](Ps/pC_snet2doorbadgeaccess.md)<br><br> physical-access<br> ↳[paxton-badge-access](Ps/pC_paxtonbadgeaccess.md)<br> ↳[s-net2door-badge-access](Ps/pC_snet2doorbadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_paxton_net2door_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |