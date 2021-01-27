Vendor: SAP
===========
Product: SAP
------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      1      |    1    |

|               Use-Case                | Activity Types                             | Event Types/Parsers                                                                                   | MITRE TTP                  | Content                   |
|:-------------------------------------:| ------------------------------------------ | ----------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Critical System Activity</li></ul> |  file-download<br> ↳ [cef-sap-app-activity-3](../Parsers/parserContent_cef-sap-app-activity-3.md)<br> | T1078 - Valid Accounts<br> | <ul><li>1 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |