Vendor: APC
===========
Product: APC
------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  14   |   10   |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  network-alert<br> ↳[apc-network-alert](Ps/pC_apcnetworkalert.md)<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br> | [<ul><li>8 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_apc_apc_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  network-alert<br> ↳[apc-network-alert](Ps/pC_apcnetworkalert.md)<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br> | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_apc_apc_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  network-alert<br> ↳[apc-network-alert](Ps/pC_apcnetworkalert.md)<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br> |    | [<ul><li>5 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_apc_apc_Other.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     |              |        |