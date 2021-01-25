Vendor: Trapx
=============
Product: Trapx
--------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   4    |     2      |      1      |    1    |

|               Use-Case                | Activity Types                                                                                            | Event Types/Parsers                                                             | MITRE TTP                                   | Content                                             |
|:-------------------------------------:| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------- | --------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Endpoint Activity</li><li>Network Alert</li><li>Process Activity</li><li>Security Alert</li></ul> |  network-alert<br> ↳ [trapx-alert](../Parsers/parserContent_trapx-alert.md)<br> | T1066 - T1066<br>T1204 - User Execution<br> | <ul><li>9 Rules</li></ul><ul><li>4 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |