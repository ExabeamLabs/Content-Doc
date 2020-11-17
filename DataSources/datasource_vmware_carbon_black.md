Vendor: VMware
==============
Product: Carbon Black
---------------------
|                              Use-Case                               | Activity Types      | Event Types/Parsers                                                                                                      | MITRE TTP                  | Content                   |
|:-------------------------------------------------------------------:| ------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------- |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | - Endpoint Activity |  process-alert<br> -- [cef-carbonblack-process-alert-1](../Parsers/parserContent_cef-carbonblack-process-alert-1.md)<br> | T1204 - User Execution<br> |  - 8 Rules<br> - 4 Models |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | - Endpoint Activity |  process-alert<br> -- [cef-carbonblack-process-alert-1](../Parsers/parserContent_cef-carbonblack-process-alert-1.md)<br> | T1204 - User Execution<br> |  - 8 Rules<br> - 4 Models |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilage escalation | Defense evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |