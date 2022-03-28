Vendor: McAfee
==============
Product: McAfee Network Security Platform (IPS)
-----------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  33   |   20   |     4      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md) |  dlp-alert<br> ↳[mcafee-ips-network-alert](Ps/pC_mcafeeipsnetworkalert.md)<br> ↳[mcafee-network-alert](Ps/pC_mcafeenetworkalert.md)<br> ↳[cef-mcafee-network-alert](Ps/pC_cefmcafeenetworkalert.md)<br> ↳[mcafee-network-alert-1](Ps/pC_mcafeenetworkalert1.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br> | [<ul><li>29 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_mcafee_mcafee_network_security_platform_(ips)_Data_Exfiltration.md) |
|         [Data Leak](../../../UseCases/uc_data_leak.md)         |  dlp-alert<br> ↳[mcafee-ips-network-alert](Ps/pC_mcafeeipsnetworkalert.md)<br> ↳[mcafee-network-alert](Ps/pC_mcafeenetworkalert.md)<br> ↳[cef-mcafee-network-alert](Ps/pC_cefmcafeenetworkalert.md)<br> ↳[mcafee-network-alert-1](Ps/pC_mcafeenetworkalert1.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br> | [<ul><li>29 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_mcafee_mcafee_network_security_platform_(ips)_Data_Leak.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-alert<br> ↳[mcafee-ips-network-alert](Ps/pC_mcafeeipsnetworkalert.md)<br> ↳[mcafee-network-alert](Ps/pC_mcafeenetworkalert.md)<br> ↳[cef-mcafee-network-alert](Ps/pC_cefmcafeenetworkalert.md)<br> ↳[mcafee-network-alert-1](Ps/pC_mcafeenetworkalert1.md)<br> | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_mcafee_mcafee_network_security_platform_(ips)_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |