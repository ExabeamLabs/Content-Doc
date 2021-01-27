Vendor: Cloudflare
==================
Product: Cloudflare CDN
-----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   4    |     2      |      1      |    1    |

|                              Use-Case                               | Activity Types                                               | Event Types/Parsers                                                                                           | MITRE TTP                  | Content                                             |
|:-------------------------------------------------------------------:| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------------------------- |
|     [Lateral Movement](../UseCases/usecase_lateral_movement.md)     | <ul><li>Network Alert</li><li>Security Alert</li></ul>       |  network-alert<br> ↳ [cloudflare-network-alert-2](../Parsers/parserContent_cloudflare-network-alert-2.md)<br> | T1066 - T1066<br>          | <ul><li>5 Rules</li></ul><ul><li>3 Models</li></ul> |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  network-alert<br> ↳ [cloudflare-network-alert-2](../Parsers/parserContent_cloudflare-network-alert-2.md)<br> | T1204 - User Execution<br> | <ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul> |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  network-alert<br> ↳ [cloudflare-network-alert-2](../Parsers/parserContent_cloudflare-network-alert-2.md)<br> | T1204 - User Execution<br> | <ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |