Vendor: Check Point
===================
Product: Check Point Threat Prevention
--------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     1      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                                              | MITRE TTP                  | Content                                                                                                                    |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  network-alert<br> ↳ [syslog-checkpoint-network-alert](Parsers/parserContent_syslog-checkpoint-network-alert.md)<br> ↳ [cef-checkpoint-network-alert](Parsers/parserContent_cef-checkpoint-network-alert.md)<br> ↳ [checkpoint-network-alert-1](Parsers/parserContent_checkpoint-network-alert-1.md)<br> ↳ [checkpoint-network-alert-1](Parsers/parserContent_checkpoint-network-alert-1.md)<br> | T1204 - User Execution<br> | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](Rules_Models/r_m_check_point_check_point_threat_prevention_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |