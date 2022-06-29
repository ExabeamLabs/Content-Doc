Vendor: Sybase
==============
Product: Sybase
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   10   |     1      |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-access<br> ↳[json-sybase-db-access-1](Ps/pC_jsonsybasedbaccess1.md)<br> ↳[json-sybase-db-access](Ps/pC_jsonsybasedbaccess.md)<br><br> database-login<br> ↳[cef-sybase-db-login](Ps/pC_cefsybasedblogin.md)<br> ↳[json-sybase-db-login](Ps/pC_jsonsybasedblogin.md)<br><br> database-query<br> ↳[json-sybase-db-query-create](Ps/pC_jsonsybasedbquerycreate.md)<br> ↳[json-sybase-db-query-delete](Ps/pC_jsonsybasedbquerydelete.md)<br> ↳[json-sybase-db-query-insert](Ps/pC_jsonsybasedbqueryinsert.md)<br> ↳[cef-sybase-db-query](Ps/pC_cefsybasedbquery.md)<br> ↳[json-sybase-db-query-select](Ps/pC_jsonsybasedbqueryselect.md)<br> ↳[json-sybase-db-query-update](Ps/pC_jsonsybasedbqueryupdate.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_sybase_sybase_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-access<br> ↳[json-sybase-db-access-1](Ps/pC_jsonsybasedbaccess1.md)<br> ↳[json-sybase-db-access](Ps/pC_jsonsybasedbaccess.md)<br><br> database-login<br> ↳[cef-sybase-db-login](Ps/pC_cefsybasedblogin.md)<br> ↳[json-sybase-db-login](Ps/pC_jsonsybasedblogin.md)<br><br> database-query<br> ↳[json-sybase-db-query-create](Ps/pC_jsonsybasedbquerycreate.md)<br> ↳[json-sybase-db-query-delete](Ps/pC_jsonsybasedbquerydelete.md)<br> ↳[json-sybase-db-query-insert](Ps/pC_jsonsybasedbqueryinsert.md)<br> ↳[cef-sybase-db-query](Ps/pC_cefsybasedbquery.md)<br> ↳[json-sybase-db-query-select](Ps/pC_jsonsybasedbqueryselect.md)<br> ↳[json-sybase-db-query-update](Ps/pC_jsonsybasedbqueryupdate.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_sybase_sybase_Data_Access.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |