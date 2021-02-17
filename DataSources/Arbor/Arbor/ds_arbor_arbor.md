Vendor: Arbor
=============
Product: Arbor
--------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  13   |   1    |     3      |      1      |    1    |

|                               Use-Case                               | Activity Types                                 | Event Types/Parsers                                                                                    | MITRE TTP                                               | Content                                                                           |
|:--------------------------------------------------------------------:| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------- | --------------------------------------------------------------------------------- |
|     [Lateral Movement](../../../UseCases/uc_lateral_movement.md)     | <ul><li>Network</li><li>Web Activity</li></ul> |  network-connection-failed<br> ↳ [arbor-network-fail](Parsers/parserContent_arbor-network-fail.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>11 Rules</li></ul>](Rules_Models/r_m_arbor_arbor_Lateral_Movement.md)    |
|    [Malware Detection](../../../UseCases/uc_malware_detection.md)    | <ul><li>Network</li></ul>                      |  network-connection-failed<br> ↳ [arbor-network-fail](Parsers/parserContent_arbor-network-fail.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>4 Rules</li></ul>](Rules_Models/r_m_arbor_arbor_Malware_Detection.md)    |
|                [Other](../../../UseCases/uc_other.md)                | <ul><li>Web Activity</li></ul>                 |  network-connection-failed<br> ↳ [arbor-network-fail](Parsers/parserContent_arbor-network-fail.md)<br> | T1496 - Resource Hijacking<br>                          | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_arbor_arbor_Other.md)                |
|             [Phishing](../../../UseCases/uc_phishing.md)             | <ul><li>Network</li></ul>                      |  network-connection-failed<br> ↳ [arbor-network-fail](Parsers/parserContent_arbor-network-fail.md)<br> | T1071 - Application Layer Protocol<br>                  | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_arbor_arbor_Phishing.md)             |
| [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md) | <ul><li>Network</li></ul>                      |  network-connection-failed<br> ↳ [arbor-network-fail](Parsers/parserContent_arbor-network-fail.md)<br> | T1071 - Application Layer Protocol<br>                  | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_arbor_arbor_Ransomware_Detection.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact                                                                  |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------- |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |