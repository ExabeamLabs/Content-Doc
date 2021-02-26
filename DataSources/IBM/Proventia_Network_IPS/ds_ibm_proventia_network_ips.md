Vendor: IBM
===========
Product: Proventia Network IPS
------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   6    |     2      |      1      |    1    |

|                               Use-Case                               | Event Types/Parsers                                                                          | MITRE TTP                  | Content                                                                                                                   |
|:--------------------------------------------------------------------:| -------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
|     [Lateral Movement](../../../UseCases/uc_lateral_movement.md)     |  network-alert<br> ↳ [q-ibm-network-alert](Parsers/parserContent_q-ibm-network-alert.md)<br> | T1066 - T1066<br>          | [<ul><li>5 Rules</li></ul><ul><li>4 Models</li></ul>](Rules_Models/r_m_ibm_proventia_network_ips_Lateral_Movement.md)     |
|    [Malware Detection](../../../UseCases/uc_malware_detection.md)    |  network-alert<br> ↳ [q-ibm-network-alert](Parsers/parserContent_q-ibm-network-alert.md)<br> | T1204 - User Execution<br> | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](Rules_Models/r_m_ibm_proventia_network_ips_Malware_Detection.md)    |
| [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md) |  network-alert<br> ↳ [q-ibm-network-alert](Parsers/parserContent_q-ibm-network-alert.md)<br> | T1204 - User Execution<br> | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](Rules_Models/r_m_ibm_proventia_network_ips_Ransomware_Detection.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |