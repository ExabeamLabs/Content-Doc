Vendor: Box Cloud Content Management
====================================
Product: Box Cloud Content Management
-------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      1      |    1    |

|                                 Use-Case                                  | Activity Types                             | Event Types/Parsers                                                                   | MITRE TTP                  | Content                   |
|:-------------------------------------------------------------------------:| ------------------------------------------ | ------------------------------------------------------------------------------------- | -------------------------- | ------------------------- |
| [Compromised Credentials](../UseCases/usecase_compromised_credentials.md) | <ul><li>Critical System Activity</li></ul> |  file-download<br> ↳ [box-activity-2](../Parsers/parserContent_box-activity-2.md)<br> | T1078 - Valid Accounts<br> | <ul><li>1 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |