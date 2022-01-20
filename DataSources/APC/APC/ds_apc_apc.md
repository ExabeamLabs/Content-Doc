Vendor: APC
===========
Product: APC
------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  25   |   10   |     5      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  network-alert<br> ↳[apc-network-alert](Ps/pC_apcnetworkalert.md)<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1190 - Exploit Public Fasing Application<br> | [<ul><li>22 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_apc_apc_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  network-alert<br> ↳[apc-network-alert](Ps/pC_apcnetworkalert.md)<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br> | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_apc_apc_Malware.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  network-alert<br> ↳[apc-network-alert](Ps/pC_apcnetworkalert.md)<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br> | T1021.002 - Remote Services: SMB/Windows Admin Shares<br>T1087 - Account Discovery<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_apc_apc_Privilege_Escalation.md)     |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                         | Execution | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access | Discovery                                                              | Lateral Movement                                                                                                                                                       | Collection | Command and Control | Exfiltration | Impact |
| -------------------------------------------------------------------------------------- | --------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
| [Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   | [Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)<br><br> |            |                     |              |        |