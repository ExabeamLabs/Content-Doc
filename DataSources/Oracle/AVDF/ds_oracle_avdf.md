Vendor: Oracle
==============
Product: AVDF
-------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  17   |   7    |     4      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  database-login<br> ↳[oracle-avdf-database-query](Ps/pC_oracleavdfdatabasequery.md)<br><br> failed-app-login<br> ↳[oracle-avdf-database-login](Ps/pC_oracleavdfdatabaselogin.md)<br> | T1133 - External Remote Services<br>    | [<ul><li>3 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_oracle_avdf_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  database-login<br> ↳[oracle-avdf-database-query](Ps/pC_oracleavdfdatabasequery.md)<br><br> failed-app-login<br> ↳[oracle-avdf-database-login](Ps/pC_oracleavdfdatabaselogin.md)<br> | T1078 - Valid Accounts<br>T1213 - Data from Information Repositories<br> | [<ul><li>11 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_oracle_avdf_Compromised_Credentials.md)         |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-login<br> ↳[oracle-avdf-database-query](Ps/pC_oracleavdfdatabasequery.md)<br><br> failed-app-login<br> ↳[oracle-avdf-database-login](Ps/pC_oracleavdfdatabaselogin.md)<br> | T1078 - Valid Accounts<br>T1213 - Data from Information Repositories<br> | [<ul><li>11 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_oracle_avdf_Data_Access.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  database-login<br> ↳[oracle-avdf-database-query](Ps/pC_oracleavdfdatabasequery.md)<br><br> failed-app-login<br> ↳[oracle-avdf-database-login](Ps/pC_oracleavdfdatabaselogin.md)<br> | T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>         | [<ul><li>1 Rules</li></ul>](RM/r_m_oracle_avdf_Lateral_Movement.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  database-login<br> ↳[oracle-avdf-database-query](Ps/pC_oracleavdfdatabasequery.md)<br><br> failed-app-login<br> ↳[oracle-avdf-database-login](Ps/pC_oracleavdfdatabaselogin.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_oracle_avdf_Privilege_Abuse.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  database-login<br> ↳[oracle-avdf-database-query](Ps/pC_oracleavdfdatabasequery.md)<br><br> failed-app-login<br> ↳[oracle-avdf-database-login](Ps/pC_oracleavdfdatabaselogin.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_oracle_avdf_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  database-login<br> ↳[oracle-avdf-database-query](Ps/pC_oracleavdfdatabasequery.md)<br><br> failed-app-login<br> ↳[oracle-avdf-database-login](Ps/pC_oracleavdfdatabaselogin.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_oracle_avdf_Ransomware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |