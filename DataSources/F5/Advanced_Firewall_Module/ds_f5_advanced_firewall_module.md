Vendor: F5
==========
Product: Advanced Firewall Module
---------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  29   |   15   |     2      |      2      |    2    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                              | MITRE TTP                                               | Content                                                                                                        |
|:--------------------------------------:| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  network-connection-failed<br> ↳ [f5-network-connection](Parsers/parserContent_f5-network-connection.md)<br><br> network-connection-successful<br> ↳ [f5-network-connection](Parsers/parserContent_f5-network-connection.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>29 Rules</li></ul><ul><li>15 Models</li></ul>](Rules_Models/r_m_f5_advanced_firewall_module_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |