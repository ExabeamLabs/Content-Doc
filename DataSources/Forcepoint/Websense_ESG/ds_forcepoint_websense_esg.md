Vendor: Forcepoint
==================
Product: Websense ESG
---------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      1      |    1    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                               | MITRE TTP                  | Content                                                                                          |
|:--------------------------------------------------------------------------:| ----------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------ |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  dlp-email-alert-in<br> ↳ [websense-dlp-email-alert-in](Parsers/parserContent_websense-dlp-email-alert-in.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_forcepoint_websense_esg_Compromised_Credentials.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |