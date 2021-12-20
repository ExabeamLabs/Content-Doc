Vendor: MSDHCP
==============
Product: MSDHCP
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  17   |   0    |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  member-removed<br> ↳[ms-dhcp](Ps/pC_msdhcp.md)<br> | T1078 - Valid Accounts<br>       | [<ul><li>2 Rules</li></ul>](RM/r_m_msdhcp_msdhcp_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  member-removed<br> ↳[ms-dhcp](Ps/pC_msdhcp.md)<br> | T1098 - Account Manipulation<br> | [<ul><li>15 Rules</li></ul>](RM/r_m_msdhcp_msdhcp_Account_Manipulation.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  member-removed<br> ↳[ms-dhcp](Ps/pC_msdhcp.md)<br> | T1098 - Account Manipulation<br> | [<ul><li>15 Rules</li></ul>](RM/r_m_msdhcp_msdhcp_Privilege_Abuse.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                                                                                                  | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |