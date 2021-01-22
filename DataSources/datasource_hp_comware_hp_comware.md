Vendor: HP Comware
==================
Product: HP Comware
-------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  34   |   3    |     3      |      1      |    1    |

|               Use-Case                | Activity Types                      | Event Types/Parsers                                                                                       | MITRE TTP                                                                            | Content                                              |
|:-------------------------------------:| ----------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Endpoint Activity</li></ul> |  process-created<br> ↳ [hp-ndcl-process-created](../Parsers/parserContent_hp-ndcl-process-created.md)<br> | T1036 - Masquerading<br>T1204 - User Execution<br>T1219 - Remote Access Software<br> | <ul><li>34 Rules</li></ul><ul><li>3 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion                                                   | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                         | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | ----------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | --------------------------------------------------------------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      | [Masquerading](https://attack.mitre.org/techniques/T1036)<br><br> |                   |           |                  |            | [Remote Access Software](https://attack.mitre.org/techniques/T1219)<br><br> |              |        |