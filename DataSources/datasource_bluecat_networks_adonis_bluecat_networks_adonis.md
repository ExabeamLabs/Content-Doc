Vendor: BlueCat Networks Adonis
===============================
Product: BlueCat Networks Adonis
--------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      1      |    1    |

|               Use-Case                | Activity Types                        | Event Types/Parsers                                                               | MITRE TTP                                                                                | Content                   |
|:-------------------------------------:| ------------------------------------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Security Operations</li></ul> |  dns-query<br> ↳ [leef-dns-query](../Parsers/parserContent_leef-dns-query.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br> | <ul><li>2 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |