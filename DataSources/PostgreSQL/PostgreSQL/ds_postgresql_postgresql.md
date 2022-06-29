Vendor: PostgreSQL
==================
Product: PostgreSQL
-------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   10   |     1      |      4      |    4    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-access<br> ↳[cef-postgresql-audit](Ps/pC_cefpostgresqlaudit.md)<br><br> database-delete<br> ↳[cef-postgresql-audit](Ps/pC_cefpostgresqlaudit.md)<br><br> database-login<br> ↳[postgresql-database-login](Ps/pC_postgresqldatabaselogin.md)<br> ↳[cef-postgresql-audit](Ps/pC_cefpostgresqlaudit.md)<br><br> database-query<br> ↳[cef-postgresql-audit](Ps/pC_cefpostgresqlaudit.md)<br> ↳[pgsql-db-query](Ps/pC_pgsqldbquery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_postgresql_postgresql_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-access<br> ↳[cef-postgresql-audit](Ps/pC_cefpostgresqlaudit.md)<br><br> database-delete<br> ↳[cef-postgresql-audit](Ps/pC_cefpostgresqlaudit.md)<br><br> database-login<br> ↳[postgresql-database-login](Ps/pC_postgresqldatabaselogin.md)<br> ↳[cef-postgresql-audit](Ps/pC_cefpostgresqlaudit.md)<br><br> database-query<br> ↳[cef-postgresql-audit](Ps/pC_cefpostgresqlaudit.md)<br> ↳[pgsql-db-query](Ps/pC_pgsqldbquery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_postgresql_postgresql_Data_Access.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |