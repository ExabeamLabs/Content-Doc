Vendor: jSONAR
==============
Product: SonarG
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  10   |   5    |     1      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  database-failed-login<br> ↳[jsonar-database-login-1](Ps/pC_jsonardatabaselogin1.md)<br><br> database-login<br> ↳[jsonar-database-login](Ps/pC_jsonardatabaselogin.md)<br> ↳[jsonar-database-login-1](Ps/pC_jsonardatabaselogin1.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>10 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_jsonar_sonarg_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  database-failed-login<br> ↳[jsonar-database-login-1](Ps/pC_jsonardatabaselogin1.md)<br><br> database-login<br> ↳[jsonar-database-login](Ps/pC_jsonardatabaselogin.md)<br> ↳[jsonar-database-login-1](Ps/pC_jsonardatabaselogin1.md)<br> | T1213 - Data from Information Repositories<br> | [<ul><li>10 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_jsonar_sonarg_Data_Access.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection                                                                              | Command and Control | Exfiltration | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------- | ------------------- | ------------ | ------ |
|                |           |             |                      |                 |                   |           |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> |                     |              |        |