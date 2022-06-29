Vendor: Mysql
=============
Product: Mysql
--------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   10   |     1      |      4      |    4    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-activity-failed<br> ↳[mysql-db-activity-json](Ps/pC_mysqldbactivityjson.md)<br><br> database-delete<br> ↳[mysql-db-activity-json](Ps/pC_mysqldbactivityjson.md)<br><br> database-query<br> ↳[syslog-mysql-dbquery-2](Ps/pC_syslogmysqldbquery2.md)<br> ↳[syslog-mysql-dbwrite](Ps/pC_syslogmysqldbwrite.md)<br> ↳[syslog-mysql-dbquery-1](Ps/pC_syslogmysqldbquery1.md)<br> ↳[syslog-mysql-dbquery](Ps/pC_syslogmysqldbquery.md)<br> ↳[mysql-db-activity-json](Ps/pC_mysqldbactivityjson.md)<br><br> database-update<br> ↳[mysql-db-activity-json](Ps/pC_mysqldbactivityjson.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_mysql_mysql_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-activity-failed<br> ↳[mysql-db-activity-json](Ps/pC_mysqldbactivityjson.md)<br><br> database-delete<br> ↳[mysql-db-activity-json](Ps/pC_mysqldbactivityjson.md)<br><br> database-query<br> ↳[syslog-mysql-dbquery-2](Ps/pC_syslogmysqldbquery2.md)<br> ↳[syslog-mysql-dbwrite](Ps/pC_syslogmysqldbwrite.md)<br> ↳[syslog-mysql-dbquery-1](Ps/pC_syslogmysqldbquery1.md)<br> ↳[syslog-mysql-dbquery](Ps/pC_syslogmysqldbquery.md)<br> ↳[mysql-db-activity-json](Ps/pC_mysqldbactivityjson.md)<br><br> database-update<br> ↳[mysql-db-activity-json](Ps/pC_mysqldbactivityjson.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_mysql_mysql_Data_Access.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |