Vendor: OneDrive
================
Product: OneDrive
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      1      |    1    |

|               Use-Case                | Activity Types                             | Event Types/Parsers                                                                                       | MITRE TTP                  | Content                   |
|:-------------------------------------:| ------------------------------------------ | --------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Critical System Activity</li></ul> |  file-read<br> ↳ [cef-onedrive-file-activity](../Parsers/parserContent_cef-onedrive-file-activity.md)<br> | T1078 - Valid Accounts<br> | <ul><li>1 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |