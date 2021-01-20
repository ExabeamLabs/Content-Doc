Vendor: Symantec DLP
====================
Product: Symantec DLP
---------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   8   |   2    |     2      |      4      |    4    |

|                              Use-Case                               | Activity Types                                               | Event Types/Parsers                                                                                                                                                                                                                                                                                                     | MITRE TTP                  | Content                                             |
|:-------------------------------------------------------------------:| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------------------------- |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  dlp-alert<br> ↳ [symantec-message-alert](../Parsers/parserContent_symantec-message-alert.md)<br> ↳ [syslog-symantec-dlp-alert-3](../Parsers/parserContent_syslog-symantec-dlp-alert-3.md)<br><br> dlp-email-alert-out<br> ↳ [syslog-symantec-dlp-alert-3](../Parsers/parserContent_syslog-symantec-dlp-alert-3.md)<br> | T1204 - User Execution<br> | <ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul> |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  dlp-alert<br> ↳ [symantec-message-alert](../Parsers/parserContent_symantec-message-alert.md)<br> ↳ [syslog-symantec-dlp-alert-3](../Parsers/parserContent_syslog-symantec-dlp-alert-3.md)<br><br> dlp-email-alert-out<br> ↳ [syslog-symantec-dlp-alert-3](../Parsers/parserContent_syslog-symantec-dlp-alert-3.md)<br> | T1204 - User Execution<br> | <ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |