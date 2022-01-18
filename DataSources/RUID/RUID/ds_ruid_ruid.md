Vendor: RUID
============
Product: RUID
-------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   2    |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  failed-app-login<br> ↳[cef-ruid-auth-success](Ps/pC_cefruidauthsuccess.md)<br> | T1133 - External Remote Services<br>   | [<ul><li>2 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_ruid_ruid_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  failed-app-login<br> ↳[cef-ruid-auth-success](Ps/pC_cefruidauthsuccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_ruid_ruid_Compromised_Credentials.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  failed-app-login<br> ↳[cef-ruid-auth-success](Ps/pC_cefruidauthsuccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_ruid_ruid_Data_Access.md)    |
|    [Evasion](../../../UseCases/uc_evasion.md)    |  failed-app-login<br> ↳[cef-ruid-auth-success](Ps/pC_cefruidauthsuccess.md)<br> | T1090.003 - Proxy: Multi-hop Proxy<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_ruid_ruid_Evasion.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  failed-app-login<br> ↳[cef-ruid-auth-success](Ps/pC_cefruidauthsuccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_ruid_ruid_Privilege_Abuse.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  failed-app-login<br> ↳[cef-ruid-auth-success](Ps/pC_cefruidauthsuccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_ruid_ruid_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  failed-app-login<br> ↳[cef-ruid-auth-success](Ps/pC_cefruidauthsuccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_ruid_ruid_Ransomware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |