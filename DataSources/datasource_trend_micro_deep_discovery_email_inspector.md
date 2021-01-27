Vendor: Trend Micro
===================
Product: Deep Discovery Email Inspector
---------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      1      |    1    |

|               Use-Case                | Activity Types                                                    | Event Types/Parsers                                                                                                              | MITRE TTP                                                                    | Content                   |
|:-------------------------------------:| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Critical System Activity</li><li>Email Activity</li></ul> |  dlp-email-alert-in<br> ↳ [cef-trendmicro-dlp-email-alert-in](../Parsers/parserContent_cef-trendmicro-dlp-email-alert-in.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1078 - Valid Accounts<br> | <ul><li>4 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------- | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |