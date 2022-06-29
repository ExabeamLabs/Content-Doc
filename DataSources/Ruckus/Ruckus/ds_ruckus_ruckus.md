Vendor: Ruckus
==============
Product: Ruckus
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  12   |   6    |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  nac-logon<br> ↳[exa-syslog-nac-logon-1](Ps/pC_exasyslognaclogon1.md)<br> ↳[exa-syslog-nac-logon-2](Ps/pC_exasyslognaclogon2.md)<br> ↳[exa-syslog-nac-logon-3](Ps/pC_exasyslognaclogon3.md)<br> ↳[exa-syslog-nac-logon-4](Ps/pC_exasyslognaclogon4.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>8 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_ruckus_ruckus_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  nac-logon<br> ↳[exa-syslog-nac-logon-1](Ps/pC_exasyslognaclogon1.md)<br> ↳[exa-syslog-nac-logon-2](Ps/pC_exasyslognaclogon2.md)<br> ↳[exa-syslog-nac-logon-3](Ps/pC_exasyslognaclogon3.md)<br> ↳[exa-syslog-nac-logon-4](Ps/pC_exasyslognaclogon4.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>6 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_ruckus_ruckus_Compromised_Credentials.md)          |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  nac-logon<br> ↳[exa-syslog-nac-logon-1](Ps/pC_exasyslognaclogon1.md)<br> ↳[exa-syslog-nac-logon-2](Ps/pC_exasyslognaclogon2.md)<br> ↳[exa-syslog-nac-logon-3](Ps/pC_exasyslognaclogon3.md)<br> ↳[exa-syslog-nac-logon-4](Ps/pC_exasyslognaclogon4.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_ruckus_ruckus_Lateral_Movement.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement                                                     | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | -------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> |            |                     |              |        |