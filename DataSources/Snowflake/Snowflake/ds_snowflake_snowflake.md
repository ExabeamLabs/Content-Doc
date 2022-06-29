Vendor: Snowflake
=================
Product: Snowflake
------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   10   |     1      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-login<br> ↳[s-snowflake-db-login-1](Ps/pC_ssnowflakedblogin1.md)<br> ↳[cef-snowflake-db-login](Ps/pC_cefsnowflakedblogin.md)<br> ↳[cef-snowflake-db-login-1](Ps/pC_cefsnowflakedblogin1.md)<br><br> database-query<br> ↳[s-snowflake-db-query-1](Ps/pC_ssnowflakedbquery1.md)<br> ↳[cef-snowflake-db-query](Ps/pC_cefsnowflakedbquery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_snowflake_snowflake_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-login<br> ↳[s-snowflake-db-login-1](Ps/pC_ssnowflakedblogin1.md)<br> ↳[cef-snowflake-db-login](Ps/pC_cefsnowflakedblogin.md)<br> ↳[cef-snowflake-db-login-1](Ps/pC_cefsnowflakedblogin1.md)<br><br> database-query<br> ↳[s-snowflake-db-query-1](Ps/pC_ssnowflakedbquery1.md)<br> ↳[cef-snowflake-db-query](Ps/pC_cefsnowflakedbquery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_snowflake_snowflake_Data_Access.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |