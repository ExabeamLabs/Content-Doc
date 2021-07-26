Vendor: Galaxy
==============
Product: Galaxy
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      1      |    1    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                                                                                                                                                         | MITRE TTP                  | Content                                                                                                          |
|:--------------------------------------------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  failed-physical-access<br> ↳ [galaxy-physical-badge-access](Parsers/parserContent_galaxy-physical-badge-access.md)<br><br> physical-access<br> ↳ [galaxy-physical-badge-access](Parsers/parserContent_galaxy-physical-badge-access.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_galaxy_galaxy_Compromised_Credentials.md) |
|       [Physical Security](../../../UseCases/uc_physical_security.md)       |  failed-physical-access<br> ↳ [galaxy-physical-badge-access](Parsers/parserContent_galaxy-physical-badge-access.md)<br><br> physical-access<br> ↳ [galaxy-physical-badge-access](Parsers/parserContent_galaxy-physical-badge-access.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_galaxy_galaxy_Physical_Security.md)                                 |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |