Vendor: Apache
==============
Product: Cassandra
------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  10   |   5    |         1          |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-login<br> ↳[cassandra-db-login](Ps/pC_cassandradblogin.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>10 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_apache_cassandra_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-login<br> ↳[cassandra-db-login](Ps/pC_cassandradblogin.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>10 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_apache_cassandra_Data_Access.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |