Vendor: Portnox
===============
Product: Portnox CLEAR
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  12   |   6    |     2      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  nac-failed-logon<br> ↳[portox-nac-failed-logon](Ps/pC_portoxnacfailedlogon.md)<br> ↳[portox-nac-failed-logon-2](Ps/pC_portoxnacfailedlogon2.md)<br> ↳[portox-nac-failed-logon-3](Ps/pC_portoxnacfailedlogon3.md)<br><br> nac-logon<br> ↳[portox-nac-logon](Ps/pC_portoxnaclogon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>12 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_portnox_portnox_clear_Abnormal_Authentication_&_Access.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement                                                     | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | -------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> |            |                     |              |        |