Vendor: F-Secure
================
Product: F-Secure Client Security
---------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  24   |   12   |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  file-permission-change<br> ↳[cef-fsecure-security-alert](Ps/pC_ceffsecuresecurityalert.md)<br> | T1083 - File and Directory Discovery<br> | [<ul><li>23 Rules</li></ul><ul><li>12 Models</li></ul>](RM/r_m_f-secure_f-secure_client_security_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  file-permission-change<br> ↳[cef-fsecure-security-alert](Ps/pC_ceffsecuresecurityalert.md)<br> | T1083 - File and Directory Discovery<br> | [<ul><li>23 Rules</li></ul><ul><li>12 Models</li></ul>](RM/r_m_f-secure_f-secure_client_security_Data_Access.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  file-permission-change<br> ↳[cef-fsecure-security-alert](Ps/pC_ceffsecuresecurityalert.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_f-secure_f-secure_client_security_Privilege_Abuse.md)    |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  file-permission-change<br> ↳[cef-fsecure-security-alert](Ps/pC_ceffsecuresecurityalert.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_f-secure_f-secure_client_security_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery                                                                         | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------------------------------------------------------------------------------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  |            |                     |              |        |