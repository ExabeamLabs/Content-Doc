Vendor: FireEye Email Threat Prevention (ETP)
=============================================
Product: FireEye Email Threat Prevention (ETP)
----------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      2      |    2    |

|               Use-Case                | Activity Types                                                    | Event Types/Parsers                                                                                                                                                                                         | MITRE TTP                                                                    | Content                   |
|:-------------------------------------:| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Critical System Activity</li><li>Email Activity</li></ul> |  dlp-email-alert-in<br> ↳ [fireeye-dlp-email](../Parsers/parserContent_fireeye-dlp-email.md)<br><br> dlp-email-alert-in-failed<br> ↳ [fireeye-dlp-email](../Parsers/parserContent_fireeye-dlp-email.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1078 - Valid Accounts<br> | <ul><li>4 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------- | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |