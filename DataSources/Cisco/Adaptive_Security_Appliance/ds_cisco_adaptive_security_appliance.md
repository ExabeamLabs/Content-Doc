Vendor: Cisco
=============
Product: Adaptive Security Appliance
------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   2    |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  print-activity<br> ↳[cisco-asa-connection-built-302013](Ps/pC_ciscoasaconnectionbuilt302013.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_cisco_adaptive_security_appliance_Abnormal_Authentication_&_Access.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  print-activity<br> ↳[cisco-asa-connection-built-302013](Ps/pC_ciscoasaconnectionbuilt302013.md)<br> | T1052 - Exfiltration Over Physical Medium<br> | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cisco_adaptive_security_appliance_Data_Leak.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |