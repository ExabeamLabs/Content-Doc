Vendor: MariaDB
===============
Product: MariaDB
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   10   |     1      |      6      |    6    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-access<br> ↳[mariadb-read](Ps/pC_mariadbread.md)<br> ↳[mariadb-read-1](Ps/pC_mariadbread1.md)<br><br> database-delete<br> ↳[mariadb-drop](Ps/pC_mariadbdrop.md)<br><br> database-failed-login<br> ↳[mariadb-failedconnect](Ps/pC_mariadbfailedconnect.md)<br><br> database-login<br> ↳[mariadb-connect-1](Ps/pC_mariadbconnect1.md)<br> ↳[mariadb-connect](Ps/pC_mariadbconnect.md)<br><br> database-query<br> ↳[mariadb-query](Ps/pC_mariadbquery.md)<br><br> database-update<br> ↳[mariadb-write](Ps/pC_mariadbwrite.md)<br> ↳[mariadb-alter](Ps/pC_mariadbalter.md)<br> ↳[mariadb-create](Ps/pC_mariadbcreate.md)<br> ↳[mariadb-write-1](Ps/pC_mariadbwrite1.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_mariadb_mariadb_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-access<br> ↳[mariadb-read](Ps/pC_mariadbread.md)<br> ↳[mariadb-read-1](Ps/pC_mariadbread1.md)<br><br> database-delete<br> ↳[mariadb-drop](Ps/pC_mariadbdrop.md)<br><br> database-failed-login<br> ↳[mariadb-failedconnect](Ps/pC_mariadbfailedconnect.md)<br><br> database-login<br> ↳[mariadb-connect-1](Ps/pC_mariadbconnect1.md)<br> ↳[mariadb-connect](Ps/pC_mariadbconnect.md)<br><br> database-query<br> ↳[mariadb-query](Ps/pC_mariadbquery.md)<br><br> database-update<br> ↳[mariadb-write](Ps/pC_mariadbwrite.md)<br> ↳[mariadb-alter](Ps/pC_mariadbalter.md)<br> ↳[mariadb-create](Ps/pC_mariadbcreate.md)<br> ↳[mariadb-write-1](Ps/pC_mariadbwrite1.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_mariadb_mariadb_Data_Access.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |