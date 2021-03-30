Vendor: IBM
===========
Product: IBM Sametime
---------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  32   |   14   |     3      |      2      |    2    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                               | MITRE TTP                                                                       | Content                                                                                             |
|:--------------------------------------:| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  app-login<br> ↳ [ibm-app-login](Parsers/parserContent_ibm-app-login.md)<br><br> failed-app-login<br> ↳ [ibm-failed-app-login](Parsers/parserContent_ibm-failed-app-login.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>T1188 - T1188<br> | [<ul><li>32 Rules</li></ul><ul><li>14 Models</li></ul>](Rules_Models/r_m_ibm_ibm_sametime_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |