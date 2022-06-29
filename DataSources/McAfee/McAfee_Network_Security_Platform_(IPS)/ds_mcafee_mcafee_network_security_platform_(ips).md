Vendor: McAfee
==============
Product: McAfee Network Security Platform (IPS)
-----------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  26   |   11   |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  network-alert<br> ↳[mcafee-ips-network-alert](Ps/pC_mcafeeipsnetworkalert.md)<br> ↳[mcafee-network-alert](Ps/pC_mcafeenetworkalert.md)<br> ↳[cef-mcafee-network-alert](Ps/pC_cefmcafeenetworkalert.md)<br> ↳[mcafee-network-alert-1](Ps/pC_mcafeenetworkalert1.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1190 - Exploit Public Fasing Application<br> | [<ul><li>22 Rules</li></ul><ul><li>9 Models</li></ul>](RM/r_m_mcafee_mcafee_network_security_platform_(ips)_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  network-alert<br> ↳[mcafee-ips-network-alert](Ps/pC_mcafeeipsnetworkalert.md)<br> ↳[mcafee-network-alert](Ps/pC_mcafeenetworkalert.md)<br> ↳[cef-mcafee-network-alert](Ps/pC_cefmcafeenetworkalert.md)<br> ↳[mcafee-network-alert-1](Ps/pC_mcafeenetworkalert1.md)<br> | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_mcafee_mcafee_network_security_platform_(ips)_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                         | Execution | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------------------------------------------------------------------------------- | --------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     |              |        |