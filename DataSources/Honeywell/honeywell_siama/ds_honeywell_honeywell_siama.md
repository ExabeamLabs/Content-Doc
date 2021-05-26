Vendor: Honeywell
=================
Product: honeywell siama
------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      1      |    1    |

|                                           Use-Case                                           | Event Types/Parsers                                                                                                            | MITRE TTP                  | Content                                                                                                                               |
|:--------------------------------------------------------------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  physical-access<br> ↳ [cef-honeywell-physical-badge-access](Parsers/parserContent_cef-honeywell-physical-badge-access.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_honeywell_honeywell_siama_Abnormal_Authentication_&_Access.md) |
|                [Physical Security](../../../UseCases/uc_physical_security.md)                |  physical-access<br> ↳ [cef-honeywell-physical-badge-access](Parsers/parserContent_cef-honeywell-physical-badge-access.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_honeywell_honeywell_siama_Physical_Security.md)                                          |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |