Vendor: McAfee
==============
Product: MDAM
-------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   10   |     1      |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-delete<br> ↳[cef-mdam-db-alert](Ps/pC_cefmdamdbalert.md)<br><br> database-query<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br><br> database-update<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_mcafee_mdam_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-delete<br> ↳[cef-mdam-db-alert](Ps/pC_cefmdamdbalert.md)<br><br> database-query<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br><br> database-update<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>18 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_mcafee_mdam_Data_Access.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |