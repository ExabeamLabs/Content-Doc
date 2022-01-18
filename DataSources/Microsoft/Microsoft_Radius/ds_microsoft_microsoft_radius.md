Vendor: Microsoft
=================
Product: Microsoft Radius
-------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  14   |   6    |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  nac-logon<br> ↳[s-radius-wireless-nac-logon](Ps/pC_sradiuswirelessnaclogon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>14 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_microsoft_microsoft_radius_Abnormal_Authentication_&_Access.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement                                                     | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | -------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> |            |                     |              |        |