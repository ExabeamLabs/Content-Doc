Vendor: ProxySG
===============
Product: ProxySG
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   3    |     4      |      4      |    4    |

|                                 Use-Case                                  | Activity Types                                      | Event Types/Parsers                                                                                                                                                                          | MITRE TTP                            | Content                                             |
|:-------------------------------------------------------------------------:| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | --------------------------------------------------- |
| [Compromised Credentials](../UseCases/usecase_compromised_credentials.md) | <ul><li>Network zones and Location Access</li></ul> |  authentication-failed<br> ↳ [proxysg-auth-failed-1](../Parsers/parserContent_proxysg-auth-failed-1.md)<br> ↳ [proxysg-auth-failed-2](../Parsers/parserContent_proxysg-auth-failed-2.md)<br> | T1133 - External Remote Services<br> | <ul><li>2 Rules</li></ul><ul><li>2 Models</li></ul> |
|        [Lateral Movement](../UseCases/usecase_lateral_movement.md)        | <ul><li>Network zones and Location Access</li></ul> |  authentication-failed<br> ↳ [proxysg-auth-failed-1](../Parsers/parserContent_proxysg-auth-failed-1.md)<br> ↳ [proxysg-auth-failed-2](../Parsers/parserContent_proxysg-auth-failed-2.md)<br> | T1133 - External Remote Services<br> | <ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul> |
|       [Malware Detection](../UseCases/usecase_malware_detection.md)       | <ul><li>Asset Logon and Access</li></ul>            |  authentication-failed<br> ↳ [proxysg-auth-failed-1](../Parsers/parserContent_proxysg-auth-failed-1.md)<br> ↳ [proxysg-auth-failed-2](../Parsers/parserContent_proxysg-auth-failed-2.md)<br> | T1188 - T1188<br>                    | <ul><li>3 Rules</li></ul>                           |
|    [Ransomware Detection](../UseCases/usecase_ransomware_detection.md)    | <ul><li>Asset Logon and Access</li></ul>            |  authentication-failed<br> ↳ [proxysg-auth-failed-1](../Parsers/parserContent_proxysg-auth-failed-1.md)<br> ↳ [proxysg-auth-failed-2](../Parsers/parserContent_proxysg-auth-failed-2.md)<br> | T1188 - T1188<br>                    | <ul><li>3 Rules</li></ul>                           |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                | Execution | Persistence                                                                   | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ----------------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br> |                      |                 |                   |           |                  |            |                     |              |        |