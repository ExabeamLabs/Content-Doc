Vendor: Microsoft
=================
Product: Windows DNSServer
--------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  21   |   11   |     1      |      4      |    4    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-failed-login<br> ↳[s-mssql-database-login-failed-xml](Ps/pC_smssqldatabaseloginfailedxml.md)<br> ↳[s-mssql-database-login-failed](Ps/pC_smssqldatabaseloginfailed.md)<br><br> database-login<br> ↳[s-mssql-database-login-xml](Ps/pC_smssqldatabaseloginxml.md)<br> ↳[s-mssql-database-login](Ps/pC_smssqldatabaselogin.md)<br><br> database-query<br> ↳[s-mssql-database-query-sl-xml](Ps/pC_smssqldatabasequeryslxml.md)<br> ↳[s-mssql-database-query-al](Ps/pC_smssqldatabasequeryal.md)<br> ↳[s-mssql-database-query-dl](Ps/pC_smssqldatabasequerydl.md)<br> ↳[s-mssql-database-query-sl](Ps/pC_smssqldatabasequerysl.md)<br> ↳[s-mssql-database-query-dl-xml](Ps/pC_smssqldatabasequerydlxml.md)<br> ↳[s-mssql-database-query-al-xml](Ps/pC_smssqldatabasequeryalxml.md)<br><br> dns-query<br> ↳[json-microsoft-dns-query](Ps/pC_jsonmicrosoftdnsquery.md)<br> ↳[xml-microsoft-dns-query](Ps/pC_xmlmicrosoftdnsquery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>19 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_microsoft_windows_dnsserver_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-failed-login<br> ↳[s-mssql-database-login-failed-xml](Ps/pC_smssqldatabaseloginfailedxml.md)<br> ↳[s-mssql-database-login-failed](Ps/pC_smssqldatabaseloginfailed.md)<br><br> database-login<br> ↳[s-mssql-database-login-xml](Ps/pC_smssqldatabaseloginxml.md)<br> ↳[s-mssql-database-login](Ps/pC_smssqldatabaselogin.md)<br><br> database-query<br> ↳[s-mssql-database-query-sl-xml](Ps/pC_smssqldatabasequeryslxml.md)<br> ↳[s-mssql-database-query-al](Ps/pC_smssqldatabasequeryal.md)<br> ↳[s-mssql-database-query-dl](Ps/pC_smssqldatabasequerydl.md)<br> ↳[s-mssql-database-query-sl](Ps/pC_smssqldatabasequerysl.md)<br> ↳[s-mssql-database-query-dl-xml](Ps/pC_smssqldatabasequerydlxml.md)<br> ↳[s-mssql-database-query-al-xml](Ps/pC_smssqldatabasequeryalxml.md)<br><br> dns-query<br> ↳[json-microsoft-dns-query](Ps/pC_jsonmicrosoftdnsquery.md)<br> ↳[xml-microsoft-dns-query](Ps/pC_xmlmicrosoftdnsquery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>19 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_microsoft_windows_dnsserver_Data_Access.md)    |
[Next Page -->>](2_ds_microsoft_windows_dnsserver.md)

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |