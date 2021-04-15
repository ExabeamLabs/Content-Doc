Vendor: AppSense Application Manager
====================================
Product: AppSense Application Manager
-------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   6    |     1      |      1      |    1    |

|                  Use-Case                  | Event Types/Parsers                                                                                                                                                                          | MITRE TTP                  | Content                                                                                                                                      |
|:------------------------------------------:| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| [Malware](../../../UseCases/uc_malware.md) |  process-alert<br> ↳ [appsense-process-alert](Parsers/parserContent_appsense-process-alert.md)<br> ↳ [leef-appsense-process-alert](Parsers/parserContent_leef-appsense-process-alert.md)<br> | T1204 - User Execution<br> | [<ul><li>9 Rules</li></ul><ul><li>6 Models</li></ul>](Rules_Models/r_m_appsense_application_manager_appsense_application_manager_Malware.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |