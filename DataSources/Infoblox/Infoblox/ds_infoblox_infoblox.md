Vendor: Infoblox
================
Product: Infoblox
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      2      |    2    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                                                                       | MITRE TTP                                                                                | Content                                                                  |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| [Other](../../../UseCases/uc_other.md) |  computer-logon<br> ↳ [n-forwarded-cef-infoblox-dhcp](Parsers/parserContent_n-forwarded-cef-infoblox-dhcp.md)<br> ↳ [s-infoblox-dhcp-1](Parsers/parserContent_s-infoblox-dhcp-1.md)<br> ↳ [s-infoblox-dhcp](Parsers/parserContent_s-infoblox-dhcp.md)<br><br> dns-query<br> ↳ [named-dns-query](Parsers/parserContent_named-dns-query.md)<br> ↳ [cef-mcafee-dns-query](Parsers/parserContent_cef-mcafee-dns-query.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br> | [<ul><li>2 Rules</li></ul>](Rules_Models/r_m_infoblox_infoblox_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |