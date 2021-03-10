Vendor: pfSense
===============
Product: pfSense
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  12   |   7    |     2      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                                                  | MITRE TTP                                               | Content                                                                                           |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  network-connection-failed<br> ↳ [pfsense-network-connection-failed](Parsers/parserContent_pfsense-network-connection-failed.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>12 Rules</li></ul><ul><li>7 Models</li></ul>](Rules_Models/r_m_pfsense_pfsense_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |