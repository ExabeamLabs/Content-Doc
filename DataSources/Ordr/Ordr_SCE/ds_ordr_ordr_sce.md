Vendor: Ordr
============
Product: Ordr SCE
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   4    |     2      |      1      |    1    |

|                               Use-Case                               | Activity Types                                               | Event Types/Parsers                                                                  | MITRE TTP                  | Content                                                                                                       |
|:--------------------------------------------------------------------:| ------------------------------------------------------------ | ------------------------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------------------------------------------- |
|     [Lateral Movement](../../../UseCases/uc_lateral_movement.md)     | <ul><li>Network Alert</li><li>Security Alert</li></ul>       |  network-alert<br> ↳ [ordr-json-alert](Parsers/parserContent_ordr-json-alert.md)<br> | T1066 - T1066<br>          | [<ul><li>5 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_ordr_ordr_sce_Lateral_Movement.md)     |
|    [Malware Detection](../../../UseCases/uc_malware_detection.md)    | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  network-alert<br> ↳ [ordr-json-alert](Parsers/parserContent_ordr-json-alert.md)<br> | T1204 - User Execution<br> | [<ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_ordr_ordr_sce_Malware_Detection.md)    |
| [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md) | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  network-alert<br> ↳ [ordr-json-alert](Parsers/parserContent_ordr-json-alert.md)<br> | T1204 - User Execution<br> | [<ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_ordr_ordr_sce_Ransomware_Detection.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |