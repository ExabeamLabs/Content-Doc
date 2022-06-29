Vendor: Apache
==============
Product: Cassandra
------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  10   |   5    |     1      |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-activity-failed<br> ↳[cassandra-db-activity-failed](Ps/pC_cassandradbactivityfailed.md)<br><br> database-login<br> ↳[cassandra-db-login](Ps/pC_cassandradblogin.md)<br><br> database-update<br> ↳[cassandra-db-update](Ps/pC_cassandradbupdate.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>10 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_apache_cassandra_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-activity-failed<br> ↳[cassandra-db-activity-failed](Ps/pC_cassandradbactivityfailed.md)<br><br> database-login<br> ↳[cassandra-db-login](Ps/pC_cassandradblogin.md)<br><br> database-update<br> ↳[cassandra-db-update](Ps/pC_cassandradbupdate.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>10 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_apache_cassandra_Data_Access.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |