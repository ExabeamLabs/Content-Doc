Vendor: SafeSend
================
Product: SafeSend
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  30   |   7    |     2      |      1      |    1    |

|               Use-Case                | Activity Types                                                    | Event Types/Parsers                                                                                                 | MITRE TTP                                                                    | Content                                              |
|:-------------------------------------:| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Critical System Activity</li><li>Email Activity</li></ul> |  dlp-email-alert-out<br> ↳ [s-safesend-dlp-email-alert](../Parsers/parserContent_s-safesend-dlp-email-alert.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1078 - Valid Accounts<br> | <ul><li>30 Rules</li></ul><ul><li>7 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------- | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |