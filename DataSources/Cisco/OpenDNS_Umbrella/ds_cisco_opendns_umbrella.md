Vendor: Cisco
=============
Product: OpenDNS Umbrella
-------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      1      |    1    |

|                Use-Case                | Activity Types                        | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                       | MITRE TTP                                                                                | Content                                                                       |
|:--------------------------------------:| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) | <ul><li>Security Operations</li></ul> |  dns-response<br> ↳ [q-cisco-dns-response](Parsers/parserContent_q-cisco-dns-response.md)<br> ↳ [cef-cisco-dns-response-1](Parsers/parserContent_cef-cisco-dns-response-1.md)<br> ↳ [cef-cisco-dns-response-sk4](Parsers/parserContent_cef-cisco-dns-response-sk4.md)<br> ↳ [cef-cisco-dns-response](Parsers/parserContent_cef-cisco-dns-response.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br> | [<ul><li>2 Rules</li></ul>](Rules_Models/r_m_cisco_opendns_umbrella_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |