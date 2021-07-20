Vendor: F5
==========
Product: BIG-IP DNS
-------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Malware](../../../UseCases/uc_malware.md) |  dns-query<br> ↳[syslog-f5-dns-query](Ps/pC_syslogf5dnsquery.md)<br> ↳[syslog-f5-dns-query-1](Ps/pC_syslogf5dnsquery1.md)<br><br> dns-response<br> ↳[syslog-f5-dns-response](Ps/pC_syslogf5dnsresponse.md)<br> ↳[s-f5-dns-response](Ps/pC_sf5dnsresponse.md)<br> ↳[syslog-f5-dns-query-1](Ps/pC_syslogf5dnsquery1.md)<br> | T1071.004 - Application Layer Protocol: DNS<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>4 Rules</li></ul>](RM/r_m_f5_big-ip_dns_Malware.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                                                                                                                                                     | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004)<br><br>[Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |