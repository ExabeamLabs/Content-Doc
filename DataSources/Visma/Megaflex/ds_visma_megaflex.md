Vendor: Visma
=============
Product: Megaflex
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  13   |   5    |     2      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity-failed<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br><br> physical-access<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_visma_megaflex_Abnormal_Authentication_&_Access.md) |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  app-activity-failed<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br><br> physical-access<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br> | T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_visma_megaflex_Lateral_Movement.md)    |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  app-activity-failed<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br><br> physical-access<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>7 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_visma_megaflex_Physical_Security.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  app-activity-failed<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br><br> physical-access<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_visma_megaflex_Privilege_Abuse.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  app-activity-failed<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br><br> physical-access<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_visma_megaflex_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-activity-failed<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br><br> physical-access<br> ↳[visma-physical-access](Ps/pC_vismaphysicalaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_visma_megaflex_Ransomware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |