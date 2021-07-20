Vendor: McAfee
==============
Product: MDAM
-------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   11   |     3      |      4      |    4    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-alert<br> ↳[cef-mdam-db-alert](Ps/pC_cefmdamdbalert.md)<br><br> database-delete<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br><br> database-query<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br><br> database-update<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br> | T1078 - Valid Accounts<br>T1213 - Data from Information Repositories<br> | [<ul><li>14 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_mcafee_mdam_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-alert<br> ↳[cef-mdam-db-alert](Ps/pC_cefmdamdbalert.md)<br><br> database-delete<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br><br> database-query<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br><br> database-update<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br> | T1213 - Data from Information Repositories<br>    | [<ul><li>5 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_mcafee_mdam_Data_Access.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  database-alert<br> ↳[cef-mdam-db-alert](Ps/pC_cefmdamdbalert.md)<br><br> database-delete<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br><br> database-query<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br><br> database-update<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br> | T1078 - Valid Accounts<br>T1204 - User Execution<br>    | [<ul><li>5 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_mcafee_mdam_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                           | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |