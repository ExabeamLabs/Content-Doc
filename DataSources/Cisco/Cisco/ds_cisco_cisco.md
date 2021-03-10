Vendor: Cisco
=============
Product: Cisco
--------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   3    |     3      |      2      |    2    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                    | MITRE TTP                                                                       | Content                                                                                      |
|:--------------------------------------:| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  authentication-failed<br> ↳ [cisco-auth-failed-1](Parsers/parserContent_cisco-auth-failed-1.md)<br><br> network-alert<br> ↳ [stealthwatch-network-alert-1](Parsers/parserContent_stealthwatch-network-alert-1.md)<br> | T1133 - External Remote Services<br>T1188 - T1188<br>T1204 - User Execution<br> | [<ul><li>7 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_cisco_cisco_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                | Execution                                                           | Persistence                                                                   | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br> |                      |                 |                   |           |                  |            |                     |              |        |