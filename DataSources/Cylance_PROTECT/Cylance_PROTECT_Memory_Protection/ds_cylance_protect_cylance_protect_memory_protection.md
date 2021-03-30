Vendor: Cylance PROTECT
=======================
Product: Cylance PROTECT Memory Protection
------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   6    |     1      |      1      |    1    |

|                               Use-Case                               | Event Types/Parsers                                                                              | MITRE TTP                  | Content                                                                                                                                           |
|:--------------------------------------------------------------------:| ------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
|    [Malware Detection](../../../UseCases/uc_malware_detection.md)    |  process-alert<br> ↳ [cylance-process-alert](Parsers/parserContent_cylance-process-alert.md)<br> | T1204 - User Execution<br> | [<ul><li>9 Rules</li></ul><ul><li>6 Models</li></ul>](Rules_Models/r_m_cylance_protect_cylance_protect_memory_protection_Malware_Detection.md)    |
| [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md) |  process-alert<br> ↳ [cylance-process-alert](Parsers/parserContent_cylance-process-alert.md)<br> | T1204 - User Execution<br> | [<ul><li>9 Rules</li></ul><ul><li>6 Models</li></ul>](Rules_Models/r_m_cylance_protect_cylance_protect_memory_protection_Ransomware_Detection.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |