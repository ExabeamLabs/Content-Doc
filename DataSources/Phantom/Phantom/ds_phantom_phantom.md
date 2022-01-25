Vendor: Phantom
===============
Product: Phantom
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      1      |    1    |

|                                    Use-Case                                    | Event Types/Parsers                                                                                     | MITRE TTP                  | Content                                                                                    |
|:------------------------------------------------------------------------------:| ------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------ |
|    [Disabled Account Abuse](../../../UseCases/uc_disabled_account_abuse.md)    |  dlp-email-alert-in<br> ↳ [s-phantom-dlp-email-in](Parsers/parserContent_s-phantom-dlp-email-in.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_phantom_phantom_Disabled_Account_Abuse.md)    |
| [Disabled Account Activity](../../../UseCases/uc_disabled_account_activity.md) |  dlp-email-alert-in<br> ↳ [s-phantom-dlp-email-in](Parsers/parserContent_s-phantom-dlp-email-in.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_phantom_phantom_Disabled_Account_Activity.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |