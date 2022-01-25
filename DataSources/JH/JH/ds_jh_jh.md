Vendor: JH
==========
Product: JH
-----------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      1      |    1    |

|                                    Use-Case                                    | Event Types/Parsers                                                                    | MITRE TTP                  | Content                                                                          |
|:------------------------------------------------------------------------------:| -------------------------------------------------------------------------------------- | -------------------------- | -------------------------------------------------------------------------------- |
|    [Disabled Account Abuse](../../../UseCases/uc_disabled_account_abuse.md)    |  file-download<br> ↳ [jh-file-download](Parsers/parserContent_jh-file-download.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_jh_jh_Disabled_Account_Abuse.md)    |
| [Disabled Account Activity](../../../UseCases/uc_disabled_account_activity.md) |  file-download<br> ↳ [jh-file-download](Parsers/parserContent_jh-file-download.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_jh_jh_Disabled_Account_Activity.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |