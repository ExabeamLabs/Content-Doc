Vendor: ProxySG
===============
Product: ProxySG
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      1      |    1    |

|               Use-Case                | Activity Types                                                                     | Event Types/Parsers                                                                                                                                                                          | MITRE TTP                                             | Content                                             |
|:-------------------------------------:| ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | --------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Asset Logon and Access</li><li>Network zones and Location Access</li></ul> |  authentication-failed<br> ↳ [proxysg-auth-failed-1](../Parsers/parserContent_proxysg-auth-failed-1.md)<br> ↳ [proxysg-auth-failed-2](../Parsers/parserContent_proxysg-auth-failed-2.md)<br> | T1133 - External Remote Services<br>T1188 - T1188<br> | <ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                | Execution | Persistence                                                                   | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ----------------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br> |                      |                 |                   |           |                  |            |                     |              |        |