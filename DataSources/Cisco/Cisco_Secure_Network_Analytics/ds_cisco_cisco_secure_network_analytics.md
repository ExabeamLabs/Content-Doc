Vendor: Cisco
=============
Product: Cisco Secure Network Analytics
---------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  26   |   11   |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  network-alert<br> ↳[leef-stealthwatch-network-alert](Ps/pC_leefstealthwatchnetworkalert.md)<br> ↳[s-stealthwatch-network-alert](Ps/pC_sstealthwatchnetworkalert.md)<br> ↳[stealthwatch-network-alert-1](Ps/pC_stealthwatchnetworkalert1.md)<br> ↳[stealthwatch-network-alert-2](Ps/pC_stealthwatchnetworkalert2.md)<br> ↳[cef-stealthwatch-network-alert](Ps/pC_cefstealthwatchnetworkalert.md)<br> ↳[stealthwatch-network-alert-3](Ps/pC_stealthwatchnetworkalert3.md)<br> ↳[stealthwatch-network-alert](Ps/pC_stealthwatchnetworkalert.md)<br> ↳[stealthwatch-network-alert-4](Ps/pC_stealthwatchnetworkalert4.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br> | [<ul><li>19 Rules</li></ul><ul><li>9 Models</li></ul>](RM/r_m_cisco_cisco_secure_network_analytics_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  network-alert<br> ↳[leef-stealthwatch-network-alert](Ps/pC_leefstealthwatchnetworkalert.md)<br> ↳[s-stealthwatch-network-alert](Ps/pC_sstealthwatchnetworkalert.md)<br> ↳[stealthwatch-network-alert-1](Ps/pC_stealthwatchnetworkalert1.md)<br> ↳[stealthwatch-network-alert-2](Ps/pC_stealthwatchnetworkalert2.md)<br> ↳[cef-stealthwatch-network-alert](Ps/pC_cefstealthwatchnetworkalert.md)<br> ↳[stealthwatch-network-alert-3](Ps/pC_stealthwatchnetworkalert3.md)<br> ↳[stealthwatch-network-alert](Ps/pC_stealthwatchnetworkalert.md)<br> ↳[stealthwatch-network-alert-4](Ps/pC_stealthwatchnetworkalert4.md)<br> | T1204 - User Execution<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_cisco_cisco_secure_network_analytics_Malware.md)    |
[Next Page -->>](2_ds_cisco_cisco_secure_network_analytics.md)

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     |              |        |