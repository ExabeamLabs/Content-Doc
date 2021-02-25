Vendor: RSA
===========
Product: RSA
------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  14   |   4    |     4      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                     | MITRE TTP                                                                                                                | Content                                                                                   |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  netflow-connection<br> ↳ [rsa-netflow-connection](Parsers/parserContent_rsa-netflow-connection.md)<br> | T1043 - T1043<br>T1046 - Network Service Scanning<br>T1048 - Exfiltration Over Alternative Protocol<br>T1065 - T1065<br> | [<ul><li>14 Rules</li></ul><ul><li>4 Models</li></ul>](Rules_Models/r_m_rsa_rsa_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery                                                                     | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | ----------------------------------------------------------------------------- | ---------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   | [Network Service Scanning](https://attack.mitre.org/techniques/T1046)<br><br> |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |