Vendor: Tanium
==============
Product: Threat Response
------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   5    |     1      |      1      |    1    |

|                              Use-Case                               | Activity Types                      | Event Types/Parsers                                                                               | MITRE TTP                  | Content                                             |
|:-------------------------------------------------------------------:| ----------------------------------- | ------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------------------------- |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | <ul><li>Endpoint Activity</li></ul> |  process-alert<br> ↳ [tanium-process-alert](../Parsers/parserContent_tanium-process-alert.md)<br> | T1204 - User Execution<br> | <ul><li>9 Rules</li></ul><ul><li>5 Models</li></ul> |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | <ul><li>Endpoint Activity</li></ul> |  process-alert<br> ↳ [tanium-process-alert](../Parsers/parserContent_tanium-process-alert.md)<br> | T1204 - User Execution<br> | <ul><li>9 Rules</li></ul><ul><li>5 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |