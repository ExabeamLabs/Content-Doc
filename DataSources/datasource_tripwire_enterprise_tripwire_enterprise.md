Vendor: Tripwire Enterprise
===========================
Product: Tripwire Enterprise
----------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |      2      |    2    |

|                              Use-Case                               | Activity Types                      | Event Types/Parsers                                                                                                                                                                                                                                                    | MITRE TTP                  | Content                   |
|:-------------------------------------------------------------------:| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------- |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | <ul><li>Endpoint Activity</li></ul> |  file-alert<br> ↳ [tripwire-file-alert-1](../Parsers/parserContent_tripwire-file-alert-1.md)<br> ↳ [tripwire-file-alert-2](../Parsers/parserContent_tripwire-file-alert-2.md)<br> ↳ [cef-tripwire-file-alert](../Parsers/parserContent_cef-tripwire-file-alert.md)<br> | T1204 - User Execution<br> | <ul><li>2 Rules</li></ul> |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | <ul><li>Endpoint Activity</li></ul> |  file-alert<br> ↳ [tripwire-file-alert-1](../Parsers/parserContent_tripwire-file-alert-1.md)<br> ↳ [tripwire-file-alert-2](../Parsers/parserContent_tripwire-file-alert-2.md)<br> ↳ [cef-tripwire-file-alert](../Parsers/parserContent_cef-tripwire-file-alert.md)<br> | T1204 - User Execution<br> | <ul><li>2 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |