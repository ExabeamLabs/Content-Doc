Vendor: Portnox
===============
Product: Portnox CLEAR
----------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  12   |   6    |         2          |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  nac-logon<br> ↳[portox-nac-logon-1](Ps/pC_portoxnaclogon1.md)<br> ↳[portox-nac-logon](Ps/pC_portoxnaclogon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>8 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_portnox_portnox_clear_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  nac-logon<br> ↳[portox-nac-logon-1](Ps/pC_portoxnaclogon1.md)<br> ↳[portox-nac-logon](Ps/pC_portoxnaclogon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>6 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_portnox_portnox_clear_Compromised_Credentials.md)          |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  nac-logon<br> ↳[portox-nac-logon-1](Ps/pC_portoxnaclogon1.md)<br> ↳[portox-nac-logon](Ps/pC_portoxnaclogon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_portnox_portnox_clear_Lateral_Movement.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement                                                     | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | -------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> |            |                     |              |        |