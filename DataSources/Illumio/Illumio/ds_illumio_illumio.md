Vendor: Illumio
===============
Product: Illumio
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  13   |   7    |     3      |      1      |    1    |

|                               Use-Case                               | Event Types/Parsers                                                                                                    | MITRE TTP                                               | Content                                                                                                      |
|:--------------------------------------------------------------------:| ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
|     [Lateral Movement](../../../UseCases/uc_lateral_movement.md)     |  network-connection-failed<br> ↳ [illumio-network-connection](Parsers/parserContent_illumio-network-connection.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>11 Rules</li></ul><ul><li>7 Models</li></ul>](Rules_Models/r_m_illumio_illumio_Lateral_Movement.md) |
|    [Malware Detection](../../../UseCases/uc_malware_detection.md)    |  network-connection-failed<br> ↳ [illumio-network-connection](Parsers/parserContent_illumio-network-connection.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](Rules_Models/r_m_illumio_illumio_Malware_Detection.md) |
|                [Other](../../../UseCases/uc_other.md)                |  network-connection-failed<br> ↳ [illumio-network-connection](Parsers/parserContent_illumio-network-connection.md)<br> | T1496 - Resource Hijacking<br>                          | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_illumio_illumio_Other.md)                                       |
|             [Phishing](../../../UseCases/uc_phishing.md)             |  network-connection-failed<br> ↳ [illumio-network-connection](Parsers/parserContent_illumio-network-connection.md)<br> | T1071 - Application Layer Protocol<br>                  | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_illumio_illumio_Phishing.md)                                    |
| [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md) |  network-connection-failed<br> ↳ [illumio-network-connection](Parsers/parserContent_illumio-network-connection.md)<br> | T1071 - Application Layer Protocol<br>                  | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_illumio_illumio_Ransomware_Detection.md)                        |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact                                                                  |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------- |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |