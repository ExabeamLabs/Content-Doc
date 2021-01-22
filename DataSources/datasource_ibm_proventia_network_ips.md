Vendor: IBM
===========
Product: Proventia Network IPS
------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     1      |      1      |    1    |

|               Use-Case                | Activity Types                                               | Event Types/Parsers                                                                             | MITRE TTP                  | Content                                             |
|:-------------------------------------:| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  network-alert<br> ↳ [q-ibm-network-alert](../Parsers/parserContent_q-ibm-network-alert.md)<br> | T1204 - User Execution<br> | <ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |