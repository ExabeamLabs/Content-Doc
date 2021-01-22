Vendor: AppSense Application Manager
====================================
Product: AppSense Application Manager
-------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   3    |     1      |      1      |    1    |

|               Use-Case                | Activity Types                      | Event Types/Parsers                                                                                   | MITRE TTP                  | Content                                             |
|:-------------------------------------:| ----------------------------------- | ----------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Endpoint Activity</li></ul> |  process-alert<br> ↳ [appsense-process-alert](../Parsers/parserContent_appsense-process-alert.md)<br> | T1204 - User Execution<br> | <ul><li>6 Rules</li></ul><ul><li>3 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |