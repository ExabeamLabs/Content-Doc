Vendor: Netdocs
===============
Product: Netdocs
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |      8      |    8    |

|                              Use-Case                               | Activity Types                      | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                                                           | MITRE TTP                  | Content                   |
|:-------------------------------------------------------------------:| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------- |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | <ul><li>Endpoint Activity</li></ul> |  file-delete<br> ↳ [netdoc-app-activity-1](../Parsers/parserContent_netdoc-app-activity-1.md)<br><br> file-read<br> ↳ [netdoc-app-activity-1](../Parsers/parserContent_netdoc-app-activity-1.md)<br><br> file-upload<br> ↳ [netdoc-app-activity-1](../Parsers/parserContent_netdoc-app-activity-1.md)<br><br> file-write<br> ↳ [netdoc-app-activity-1](../Parsers/parserContent_netdoc-app-activity-1.md)<br> | T1204 - User Execution<br> | <ul><li>2 Rules</li></ul> |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | <ul><li>Endpoint Activity</li></ul> |  file-delete<br> ↳ [netdoc-app-activity-1](../Parsers/parserContent_netdoc-app-activity-1.md)<br><br> file-read<br> ↳ [netdoc-app-activity-1](../Parsers/parserContent_netdoc-app-activity-1.md)<br><br> file-upload<br> ↳ [netdoc-app-activity-1](../Parsers/parserContent_netdoc-app-activity-1.md)<br><br> file-write<br> ↳ [netdoc-app-activity-1](../Parsers/parserContent_netdoc-app-activity-1.md)<br> | T1204 - User Execution<br> | <ul><li>2 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |