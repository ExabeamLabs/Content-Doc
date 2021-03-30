Vendor: AppSense Application Manager
====================================
Product: AppSense Application Manager
-------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   4    |     1      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                | MITRE TTP                  | Content                                                                                                                                    |
|:--------------------------------------:| -------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| [Other](../../../UseCases/uc_other.md) |  process-alert<br> ↳ [appsense-process-alert](Parsers/parserContent_appsense-process-alert.md)<br> | T1204 - User Execution<br> | [<ul><li>6 Rules</li></ul><ul><li>4 Models</li></ul>](Rules_Models/r_m_appsense_application_manager_appsense_application_manager_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |