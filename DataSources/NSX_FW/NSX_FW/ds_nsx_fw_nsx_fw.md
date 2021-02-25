Vendor: NSX FW
==============
Product: NSX FW
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  29   |   15   |     2      |      2      |    2    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                              | MITRE TTP                                               | Content                                                                                          |
|:--------------------------------------:| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [Other](../../../UseCases/uc_other.md) |  network-connection-failed<br> ↳ [cef-nsx-fw-logs-1](Parsers/parserContent_cef-nsx-fw-logs-1.md)<br><br> network-connection-successful<br> ↳ [cef-nsx-fw-logs-1](Parsers/parserContent_cef-nsx-fw-logs-1.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>29 Rules</li></ul><ul><li>15 Models</li></ul>](Rules_Models/r_m_nsx_fw_nsx_fw_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |