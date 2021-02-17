Vendor: Airlock Web Application Firewall
========================================
Product: Airlock Web Application Firewall
-----------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  29   |   1    |     2      |      2      |    2    |

|                Use-Case                | Activity Types                                 | Event Types/Parsers                                                                                                                                                                                                                                                                      | MITRE TTP                                               | Content                                                                                                                   |
|:--------------------------------------:| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) | <ul><li>Network</li><li>Web Activity</li></ul> |  network-connection-failed<br> ↳ [airlock-firewall-network-connection](Parsers/parserContent_airlock-firewall-network-connection.md)<br><br> network-connection-successful<br> ↳ [airlock-firewall-network-connection](Parsers/parserContent_airlock-firewall-network-connection.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>29 Rules</li></ul>](Rules_Models/r_m_airlock_web_application_firewall_airlock_web_application_firewall_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |