Vendor: Cisco
=============
Product: Adaptive Security Appliance
------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   0    |     5      |      3      |    3    |

|                              Use-Case                               | Activity Types                        | Event Types/Parsers                                                                      | MITRE TTP                                                                                | Content                   |
|:-------------------------------------------------------------------:| ------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------- |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | <ul><li>Security Operations</li></ul> |  dns-response<br> ↳ [cisco-asa-746016](../Parsers/parserContent_cisco-asa-746016.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br> | <ul><li>2 Rules</li></ul> |
|             [Phishing](../UseCases/usecase_phishing.md)             | <ul><li>Security Operations</li></ul> |  dns-response<br> ↳ [cisco-asa-746016](../Parsers/parserContent_cisco-asa-746016.md)<br> | T1071 - Application Layer Protocol<br>                                                   | <ul><li>1 Rules</li></ul> |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | <ul><li>Security Operations</li></ul> |  dns-response<br> ↳ [cisco-asa-746016](../Parsers/parserContent_cisco-asa-746016.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br> | <ul><li>2 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |