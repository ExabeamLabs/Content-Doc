Vendor: Oracle
==============
Product: AVDF
-------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   11   |     1      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-query<br> ↳[oracle-avdf-database-query](Ps/pC_oracleavdfdatabasequery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>19 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_oracle_avdf_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-query<br> ↳[oracle-avdf-database-query](Ps/pC_oracleavdfdatabasequery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>19 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_oracle_avdf_Data_Access.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |