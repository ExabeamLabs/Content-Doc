Vendor: Splunk
==============
Product: Splunk Stream
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      2      |    2    |

|               Use-Case                | Activity Types                        | Event Types/Parsers                                                                                                                                                                                                     | MITRE TTP                                                                                | Content                   |
|:-------------------------------------:| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Security Operations</li></ul> |  dns-query<br> ↳ [s-splunkstream-dns-query](../Parsers/parserContent_s-splunkstream-dns-query.md)<br><br> dns-response<br> ↳ [s-splunkstream-dns-response](../Parsers/parserContent_s-splunkstream-dns-response.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br> | <ul><li>4 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |