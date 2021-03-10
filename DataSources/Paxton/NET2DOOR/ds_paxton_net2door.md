Vendor: Paxton
==============
Product: NET2DOOR
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                         | MITRE TTP                  | Content                                                                                          |
|:--------------------------------------:| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------ |
| [Other](../../../UseCases/uc_other.md) |  failed-physical-access<br> ↳ [paxton-badge-access](Parsers/parserContent_paxton-badge-access.md)<br> ↳ [s-net2door-badge-access](Parsers/parserContent_s-net2door-badge-access.md)<br><br> physical-access<br> ↳ [paxton-badge-access](Parsers/parserContent_paxton-badge-access.md)<br> ↳ [s-net2door-badge-access](Parsers/parserContent_s-net2door-badge-access.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_paxton_net2door_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |