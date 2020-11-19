Vendor: Arbor
=============
Product: Arbor
--------------
|                              Use-Case                               | Activity Types              | Event Types/Parsers                                                                                        | MITRE TTP                                                                             | Content         |
|:-------------------------------------------------------------------:| --------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------------- |
|     [Lateral Movement](../UseCases/usecase_lateral_movement.md)     | - Network<br>- Web Activity |  network-connection-failed<br> -- [arbor-network-fail](../Parsers/parserContent_arbor-network-fail.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br>                               |  - 11 Rules<br> |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | - Network<br>- Web Activity |  network-connection-failed<br> -- [arbor-network-fail](../Parsers/parserContent_arbor-network-fail.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br>T1496 - Resource Hijacking<br> |  - 5 Rules<br>  |
|             [Phishing](../UseCases/usecase_phishing.md)             | - Network                   |  network-connection-failed<br> -- [arbor-network-fail](../Parsers/parserContent_arbor-network-fail.md)<br> | T1071 - Application Layer Protocol<br>                                                |  - 1 Rules<br>  |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | - Network<br>- Web Activity |  network-connection-failed<br> -- [arbor-network-fail](../Parsers/parserContent_arbor-network-fail.md)<br> | T1071 - Application Layer Protocol<br>T1496 - Resource Hijacking<br>                  |  - 2 Rules<br>  |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilage escalation | Defense evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact                                                                  |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------- |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |