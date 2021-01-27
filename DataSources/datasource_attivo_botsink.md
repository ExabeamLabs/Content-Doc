Vendor: Attivo
==============
Product: BOTsink
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  17   |   1    |     2      |      1      |    1    |

|               Use-Case                | Activity Types                                 | Event Types/Parsers                                                                                                                 | MITRE TTP                                               | Content                    |
|:-------------------------------------:| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | -------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Network</li><li>Web Activity</li></ul> |  network-connection-successful<br> ↳ [cef-attivo-network-connection](../Parsers/parserContent_cef-attivo-network-connection.md)<br> | T1065 - T1065<br>T1071 - Application Layer Protocol<br> | <ul><li>17 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |