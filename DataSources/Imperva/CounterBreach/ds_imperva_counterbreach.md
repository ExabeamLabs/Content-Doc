Vendor: Imperva
===============
Product: CounterBreach
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  34   |   17   |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-alert<br> ↳[cef-counterbreach-db-alert](Ps/pC_cefcounterbreachdbalert.md)<br> | T1078 - Valid Accounts<br>T1213 - Data from Information Repositories<br> | [<ul><li>28 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_imperva_counterbreach_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-alert<br> ↳[cef-counterbreach-db-alert](Ps/pC_cefcounterbreachdbalert.md)<br> | T1213 - Data from Information Repositories<br>    | [<ul><li>17 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_imperva_counterbreach_Data_Access.md)    |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  database-alert<br> ↳[cef-counterbreach-db-alert](Ps/pC_cefcounterbreachdbalert.md)<br> | T1204 - User Execution<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_imperva_counterbreach_Data_Exfiltration.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  database-alert<br> ↳[cef-counterbreach-db-alert](Ps/pC_cefcounterbreachdbalert.md)<br> | T1078 - Valid Accounts<br>T1204 - User Execution<br>    | [<ul><li>5 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_imperva_counterbreach_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                           | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |