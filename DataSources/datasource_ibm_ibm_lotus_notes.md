Vendor: IBM
===========
Product: IBM Lotus Notes
------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  17   |   1    |     2      |      2      |    2    |

|               Use-Case                | Activity Types                                 | Event Types/Parsers                                                                                                                                                                                                                                | MITRE TTP                                               | Content                    |
|:-------------------------------------:| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | -------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Network</li><li>Web Activity</li></ul> |  database-update<br> ↳ [ibm-lotus-database-update](../Parsers/parserContent_ibm-lotus-database-update.md)<br><br> network-connection-successful<br> ↳ [ibm-lotus-network-connection](../Parsers/parserContent_ibm-lotus-network-connection.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | <ul><li>17 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |