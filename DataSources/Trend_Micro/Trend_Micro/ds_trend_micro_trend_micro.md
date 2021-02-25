Vendor: Trend Micro
===================
Product: Trend Micro
--------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  29   |   15   |     2      |      3      |    3    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                                                        | MITRE TTP                                               | Content                                                                                                    |
|:--------------------------------------:| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  database-failed-login<br> ↳ [cef-trendmicro-database-failed-login](Parsers/parserContent_cef-trendmicro-database-failed-login.md)<br><br> network-connection-failed<br> ↳ [trendmicro-network-connection](Parsers/parserContent_trendmicro-network-connection.md)<br><br> network-connection-successful<br> ↳ [trendmicro-network-connection](Parsers/parserContent_trendmicro-network-connection.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | [<ul><li>29 Rules</li></ul><ul><li>15 Models</li></ul>](Rules_Models/r_m_trend_micro_trend_micro_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |