Vendor: ProxySG
===============
Product: ProxySG
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   2    |     2      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                    | MITRE TTP                                             | Content                                                                                          |
|:--------------------------------------:| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [Other](../../../UseCases/uc_other.md) |  authentication-failed<br> ↳ [proxysg-auth-failed-1](Parsers/parserContent_proxysg-auth-failed-1.md)<br> ↳ [proxysg-auth-failed-2](Parsers/parserContent_proxysg-auth-failed-2.md)<br> | T1133 - External Remote Services<br>T1188 - T1188<br> | [<ul><li>5 Rules</li></ul><ul><li>2 Models</li></ul>](Rules_Models/r_m_proxysg_proxysg_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                | Execution | Persistence                                                                   | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ----------------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br> |                      |                 |                   |           |                  |            |                     |              |        |