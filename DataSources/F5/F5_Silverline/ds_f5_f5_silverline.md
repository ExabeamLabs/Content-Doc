Vendor: F5
==========
Product: F5 Silverline
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  26   |   11   |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  network-alert<br> ↳[f5-silverline-network-alert-1](Ps/pC_f5silverlinenetworkalert1.md)<br> ↳[f5-silverline-waf](Ps/pC_f5silverlinewaf.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br> | [<ul><li>19 Rules</li></ul><ul><li>9 Models</li></ul>](RM/r_m_f5_f5_silverline_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  network-alert<br> ↳[f5-silverline-network-alert-1](Ps/pC_f5silverlinenetworkalert1.md)<br> ↳[f5-silverline-waf](Ps/pC_f5silverlinewaf.md)<br> | T1204 - User Execution<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_f5_f5_silverline_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  network-alert<br> ↳[f5-silverline-network-alert-1](Ps/pC_f5silverlinenetworkalert1.md)<br> ↳[f5-silverline-waf](Ps/pC_f5silverlinewaf.md)<br> |    | [<ul><li>5 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_f5_f5_silverline_Other.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     |              |        |