Vendor: Symantec
================
Product: Symantec Managed Security Services
-------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  22   |   10   |     4      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  network-alert<br> ↳[syslog-symantec-mss-alert](Ps/pC_syslogsymantecmssalert.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>          | [<ul><li>19 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_symantec_symantec_managed_security_services_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  network-alert<br> ↳[syslog-symantec-mss-alert](Ps/pC_syslogsymantecmssalert.md)<br> | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_symantec_symantec_managed_security_services_Malware.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  network-alert<br> ↳[syslog-symantec-mss-alert](Ps/pC_syslogsymantecmssalert.md)<br> | T1021.002 - Remote Services: SMB/Windows Admin Shares<br>T1087 - Account Discovery<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_symantec_symantec_managed_security_services_Privilege_Escalation.md)     |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access | Discovery                                                              | Lateral Movement                                                                                                                                                       | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
|                |           |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   | [Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)<br><br> |            |                     |              |        |