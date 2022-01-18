Vendor: Microsoft
=================
Product: Microsoft Windows DNSServer
------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Malware](../../../UseCases/uc_malware.md) |  dns-query<br> ↳[json-microsoft-dns-query](Ps/pC_jsonmicrosoftdnsquery.md)<br> ↳[xml-microsoft-dns-query](Ps/pC_xmlmicrosoftdnsquery.md)<br> | T1071.004 - Application Layer Protocol: DNS<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_microsoft_microsoft_windows_dnsserver_Malware.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                     | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |