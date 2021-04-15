Vendor: Armis
=============
Product: Armis
--------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     1      |      1      |    1    |

|                                    Use-Case                                    | Event Types/Parsers                                                              | MITRE TTP                  | Content                                                                                |
|:------------------------------------------------------------------------------:| -------------------------------------------------------------------------------- | -------------------------- | -------------------------------------------------------------------------------------- |
| [3rd Party Security Alerts](../../../UseCases/uc_3rd_party_security_alerts.md) |  alert-iot<br> ↳ [armis-alert-iot](Parsers/parserContent_armis-alert-iot.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>3 Rules</li></ul>](Rules_Models/r_m_armis_armis_3rd_Party_Security_Alerts.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |