Vendor: Infoblox
================
Product: NIOS
-------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  24   |   11   |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  process-alert<br> ↳[infoblox-nios-dns-query](Ps/pC_infobloxniosdnsquery.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>TA0002 - TA0002<br> | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_infoblox_nios_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  process-alert<br> ↳[infoblox-nios-dns-query](Ps/pC_infobloxniosdnsquery.md)<br> | TA0002 - TA0002<br>    | [<ul><li>20 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_infoblox_nios_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                |           |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     |              |        |