Vendor: McAfee
==============
Product: McAfee IDPS
--------------------
|                              Use-Case                               | Activity Types                            | Event Types/Parsers                                                                                          | MITRE TTP                  | Content                   |
|:-------------------------------------------------------------------:| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------- |
|     [Lateral Movement](../UseCases/usecase_lateral_movement.md)     | - Network Alert<br>- Security Alert       |  network-alert<br> -- [mcafee-idps-network-alert](../Parsers/parserContent_mcafee-idps-network-alert.md)<br> | T1066 - T1066<br>          |  - 5 Rules<br> - 3 Models |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | - Endpoint Activity<br>- Process Activity |  network-alert<br> -- [mcafee-idps-network-alert](../Parsers/parserContent_mcafee-idps-network-alert.md)<br> | T1204 - User Execution<br> |  - 4 Rules<br> - 1 Models |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | - Endpoint Activity<br>- Process Activity |  network-alert<br> -- [mcafee-idps-network-alert](../Parsers/parserContent_mcafee-idps-network-alert.md)<br> | T1204 - User Execution<br> |  - 4 Rules<br> - 1 Models |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilage escalation | Defense evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |