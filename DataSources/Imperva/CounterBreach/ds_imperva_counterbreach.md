Vendor: Imperva
===============
Product: CounterBreach
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  36   |   19   |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-alert<br> ↳[cef-counterbreach-db-alert](Ps/pC_cefcounterbreachdbalert.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>32 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_imperva_counterbreach_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-alert<br> ↳[cef-counterbreach-db-alert](Ps/pC_cefcounterbreachdbalert.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>32 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_imperva_counterbreach_Data_Access.md)    |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  database-alert<br> ↳[cef-counterbreach-db-alert](Ps/pC_cefcounterbreachdbalert.md)<br> | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_imperva_counterbreach_Data_Exfiltration.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  database-alert<br> ↳[cef-counterbreach-db-alert](Ps/pC_cefcounterbreachdbalert.md)<br> | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_imperva_counterbreach_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |