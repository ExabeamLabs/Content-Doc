Vendor: Microsoft
=================
Product: Microsoft Windows DNSServer
------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      1      |    1    |

|                               Use-Case                               | Event Types/Parsers                                                                              | MITRE TTP                                                                                | Content                                                                                                     |
|:--------------------------------------------------------------------:| ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
|    [Malware Detection](../../../UseCases/uc_malware_detection.md)    |  dns-query<br> ↳ [xml-microsoft-dns-query](Parsers/parserContent_xml-microsoft-dns-query.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br> | [<ul><li>2 Rules</li></ul>](Rules_Models/r_m_microsoft_microsoft_windows_dnsserver_Malware_Detection.md)    |
|             [Phishing](../../../UseCases/uc_phishing.md)             |  dns-query<br> ↳ [xml-microsoft-dns-query](Parsers/parserContent_xml-microsoft-dns-query.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br> | [<ul><li>2 Rules</li></ul>](Rules_Models/r_m_microsoft_microsoft_windows_dnsserver_Phishing.md)             |
| [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md) |  dns-query<br> ↳ [xml-microsoft-dns-query](Parsers/parserContent_xml-microsoft-dns-query.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br> | [<ul><li>2 Rules</li></ul>](Rules_Models/r_m_microsoft_microsoft_windows_dnsserver_Ransomware_Detection.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |