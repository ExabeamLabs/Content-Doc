Vendor: McAfee
==============
Product: MDAM
-------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  42   |   22   |         2          |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-alert<br> ↳[cef-mdam-db-alert-1](Ps/pC_cefmdamdbalert1.md)<br> ↳[cef-mdam-db-alert](Ps/pC_cefmdamdbalert.md)<br><br> database-query<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>38 Rules</li></ul><ul><li>20 Models</li></ul>](RM/r_m_mcafee_mdam_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-alert<br> ↳[cef-mdam-db-alert-1](Ps/pC_cefmdamdbalert1.md)<br> ↳[cef-mdam-db-alert](Ps/pC_cefmdamdbalert.md)<br><br> database-query<br> ↳[s-mdam-db-query](Ps/pC_smdamdbquery.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>38 Rules</li></ul><ul><li>20 Models</li></ul>](RM/r_m_mcafee_mdam_Data_Access.md)    |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  database-alert<br> ↳[cef-mdam-db-alert-1](Ps/pC_cefmdamdbalert1.md)<br> ↳[cef-mdam-db-alert](Ps/pC_cefmdamdbalert.md)<br>    | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_mcafee_mdam_Data_Exfiltration.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  database-alert<br> ↳[cef-mdam-db-alert-1](Ps/pC_cefmdamdbalert1.md)<br> ↳[cef-mdam-db-alert](Ps/pC_cefmdamdbalert.md)<br>    | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_mcafee_mdam_Malware.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |