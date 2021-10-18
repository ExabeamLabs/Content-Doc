Vendor: MariaDB
===============
Product: MariaDB
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   11   |     1      |      5      |    5    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-access<br> ↳[mariadb-read](Ps/pC_mariadbread.md)<br><br> database-delete<br> ↳[mariadb-drop](Ps/pC_mariadbdrop.md)<br><br> database-login<br> ↳[mariadb-connect](Ps/pC_mariadbconnect.md)<br><br> database-query<br> ↳[mariadb-query](Ps/pC_mariadbquery.md)<br><br> database-update<br> ↳[mariadb-write](Ps/pC_mariadbwrite.md)<br> ↳[mariadb-alter](Ps/pC_mariadbalter.md)<br> ↳[mariadb-create](Ps/pC_mariadbcreate.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>19 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_mariadb_mariadb_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-access<br> ↳[mariadb-read](Ps/pC_mariadbread.md)<br><br> database-delete<br> ↳[mariadb-drop](Ps/pC_mariadbdrop.md)<br><br> database-login<br> ↳[mariadb-connect](Ps/pC_mariadbconnect.md)<br><br> database-query<br> ↳[mariadb-query](Ps/pC_mariadbquery.md)<br><br> database-update<br> ↳[mariadb-write](Ps/pC_mariadbwrite.md)<br> ↳[mariadb-alter](Ps/pC_mariadbalter.md)<br> ↳[mariadb-create](Ps/pC_mariadbcreate.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>19 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_mariadb_mariadb_Data_Access.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |