Vendor: F5
==========
Product: Advanced Firewall Module
---------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  29   |   0    |     2      |      2      |    2    |

|               Use-Case                | Activity Types                                 | Event Types/Parsers                                                                                                                                                                                                                    | MITRE TTP                                               | Content                    |
|:-------------------------------------:| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | -------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Network</li><li>Web Activity</li></ul> |  network-connection-failed<br> ↳ [f5-network-connection](../Parsers/parserContent_f5-network-connection.md)<br><br> network-connection-successful<br> ↳ [f5-network-connection](../Parsers/parserContent_f5-network-connection.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | <ul><li>29 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |