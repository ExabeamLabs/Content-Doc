Vendor: Arbor
=============
Product: Arbor
--------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  14   |   7    |     4      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                    | MITRE TTP                                                                                                                              | Content                                                                                       |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  network-connection-failed<br> ↳ [arbor-network-fail](Parsers/parserContent_arbor-network-fail.md)<br> | T1071 - Application Layer Protocol<br>T1090.002 - Proxy: External Proxy<br>T1496 - Resource Hijacking<br>T1571 - Non-Standard Port<br> | [<ul><li>14 Rules</li></ul><ul><li>7 Models</li></ul>](Rules_Models/r_m_arbor_arbor_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                                                                                           | Exfiltration | Impact                                                                  |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------- |
|                |           |             |                      |                 |                   |           |                  |            | [Non-Standard Port](https://attack.mitre.org/techniques/T1571)<br><br>[Proxy: External Proxy](https://attack.mitre.org/techniques/T1090/002)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |