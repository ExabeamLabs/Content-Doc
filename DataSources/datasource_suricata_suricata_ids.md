Vendor: Suricata
================
Product: Suricata IDS
---------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  13   |   5    |     3      |      3      |    3    |

|                              Use-Case                               | Activity Types                                               | Event Types/Parsers                                                                                   | MITRE TTP                                                                     | Content                                             |
|:-------------------------------------------------------------------:| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------------- |
|     [Lateral Movement](../UseCases/usecase_lateral_movement.md)     | <ul><li>Network Alert</li><li>Security Alert</li></ul>       |  network-alert<br> ↳ [suricata-network-alert](../Parsers/parserContent_suricata-network-alert.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br> | <ul><li>5 Rules</li></ul><ul><li>3 Models</li></ul> |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  network-alert<br> ↳ [suricata-network-alert](../Parsers/parserContent_suricata-network-alert.md)<br> | T1204 - User Execution<br>                                                    | <ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul> |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  network-alert<br> ↳ [suricata-network-alert](../Parsers/parserContent_suricata-network-alert.md)<br> | T1204 - User Execution<br>                                                    | <ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     |              |        |