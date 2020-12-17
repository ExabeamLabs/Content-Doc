Vendor: AppSense Application Manager
====================================
Product: AppSense Application Manager
-------------------------------------
|                              Use-Case                               | Activity Types      | Event Types/Parsers                                                                                                                                                                                  | MITRE TTP                  | Content                   |
|:-------------------------------------------------------------------:| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------- |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | - Endpoint Activity |  process-alert<br> -- [appsense-process-alert](../Parsers/parserContent_appsense-process-alert.md)<br> -- [leef-appsense-process-alert](../Parsers/parserContent_leef-appsense-process-alert.md)<br> | T1204 - User Execution<br> |  - 9 Rules<br> - 5 Models |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | - Endpoint Activity |  process-alert<br> -- [appsense-process-alert](../Parsers/parserContent_appsense-process-alert.md)<br> -- [leef-appsense-process-alert](../Parsers/parserContent_leef-appsense-process-alert.md)<br> | T1204 - User Execution<br> |  - 9 Rules<br> - 5 Models |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilage escalation | Defense evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |