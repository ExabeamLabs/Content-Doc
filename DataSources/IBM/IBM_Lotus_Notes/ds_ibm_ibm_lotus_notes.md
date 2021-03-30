Vendor: IBM
===========
Product: IBM Lotus Notes
------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  17   |   13   |     2      |      2      |    2    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                                          | MITRE TTP                                               | Content                                                                                                |
|:--------------------------------------:| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [Other](../../../UseCases/uc_other.md) |  database-update<br> ↳ [ibm-lotus-database-update](Parsers/parserContent_ibm-lotus-database-update.md)<br><br> network-connection-successful<br> ↳ [ibm-lotus-network-connection](Parsers/parserContent_ibm-lotus-network-connection.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>17 Rules</li></ul><ul><li>13 Models</li></ul>](Rules_Models/r_m_ibm_ibm_lotus_notes_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |