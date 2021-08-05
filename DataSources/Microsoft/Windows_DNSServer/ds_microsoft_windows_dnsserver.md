Vendor: Microsoft
=================
Product: Windows DNSServer
--------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      4      |    4    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Malware](../../../UseCases/uc_malware.md) |  database-failed-login<br> ↳[s-mssql-database-login-failed-xml](Ps/pC_smssqldatabaseloginfailedxml.md)<br> ↳[s-mssql-database-login-failed](Ps/pC_smssqldatabaseloginfailed.md)<br><br> database-login<br> ↳[s-mssql-database-login-xml](Ps/pC_smssqldatabaseloginxml.md)<br> ↳[s-mssql-database-login](Ps/pC_smssqldatabaselogin.md)<br><br> database-query<br> ↳[s-mssql-database-query-sl-xml](Ps/pC_smssqldatabasequeryslxml.md)<br> ↳[s-mssql-database-query-al](Ps/pC_smssqldatabasequeryal.md)<br> ↳[s-mssql-database-query-dl](Ps/pC_smssqldatabasequerydl.md)<br> ↳[s-mssql-database-query-sl](Ps/pC_smssqldatabasequerysl.md)<br> ↳[s-mssql-database-query-dl-xml](Ps/pC_smssqldatabasequerydlxml.md)<br> ↳[s-mssql-database-query-al-xml](Ps/pC_smssqldatabasequeryalxml.md)<br><br> dns-query<br> ↳[json-microsoft-dns-query](Ps/pC_jsonmicrosoftdnsquery.md)<br> ↳[xml-microsoft-dns-query](Ps/pC_xmlmicrosoftdnsquery.md)<br> | T1071.004 - Application Layer Protocol: DNS<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>2 Rules</li></ul>](RM/r_m_microsoft_windows_dnsserver_Malware.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                                                                                                                                                     | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004)<br><br>[Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |