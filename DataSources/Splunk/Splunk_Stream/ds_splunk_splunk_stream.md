Vendor: Splunk
==============
Product: Splunk Stream
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |      3      |    3    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                                                                                                    | MITRE TTP                                                                                | Content                                                                     |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  computer-logon<br> ↳ [s-stream-dhcp](Parsers/parserContent_s-stream-dhcp.md)<br><br> dns-query<br> ↳ [s-splunkstream-dns-query](Parsers/parserContent_s-splunkstream-dns-query.md)<br><br> dns-response<br> ↳ [s-splunkstream-dns-response](Parsers/parserContent_s-splunkstream-dns-response.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br> | [<ul><li>4 Rules</li></ul>](Rules_Models/r_m_splunk_splunk_stream_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |