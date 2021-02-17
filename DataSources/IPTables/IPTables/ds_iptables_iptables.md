Vendor: IPTables
================
Product: IPTables
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  29   |   1    |     2      |      2      |    2    |

|                Use-Case                | Activity Types                                 | Event Types/Parsers                                                                                                                                                                                                                                                                          | MITRE TTP                                               | Content                                                                   |
|:--------------------------------------:| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) | <ul><li>Network</li><li>Web Activity</li></ul> |  network-connection-failed<br> ↳ [iptables-network-connection-failed](Parsers/parserContent_iptables-network-connection-failed.md)<br><br> network-connection-successful<br> ↳ [iptables-network-connection-successful](Parsers/parserContent_iptables-network-connection-successful.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>29 Rules</li></ul>](Rules_Models/r_m_iptables_iptables_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |