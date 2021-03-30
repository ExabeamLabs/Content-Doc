Vendor: HP Aruba
================
Product: HP Aruba
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   3    |     2      |      3      |    3    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                                                                                        | MITRE TTP                                             | Content                                                                                            |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  computer-logon<br> ↳ [aruba-nac-logon](Parsers/parserContent_aruba-nac-logon.md)<br><br> nac-failed-logon<br> ↳ [cef-aruba-nac-failed-logon](Parsers/parserContent_cef-aruba-nac-failed-logon.md)<br><br> nac-logon<br> ↳ [aruba-nac-logon](Parsers/parserContent_aruba-nac-logon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>4 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_hp_aruba_hp_aruba_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement                                                     | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | -------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> |            |                     |              |        |