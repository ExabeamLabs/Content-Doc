Vendor: RSA
===========
Product: RSA NetWitness
-----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  36   |   17   |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  member-added<br> ↳[cef-rsa-app-login-1](Ps/pC_cefrsaapplogin1.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_rsa_rsa_netwitness_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  member-added<br> ↳[cef-rsa-app-login-1](Ps/pC_cefrsaapplogin1.md)<br> | T1098 - Account Manipulation<br>T1136 - Create Account<br> | [<ul><li>32 Rules</li></ul><ul><li>16 Models</li></ul>](RM/r_m_rsa_rsa_netwitness_Account_Manipulation.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  member-added<br> ↳[cef-rsa-app-login-1](Ps/pC_cefrsaapplogin1.md)<br> |    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_rsa_rsa_netwitness_Other.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  member-added<br> ↳[cef-rsa-app-login-1](Ps/pC_cefrsaapplogin1.md)<br> | T1098 - Account Manipulation<br>T1136 - Create Account<br> | [<ul><li>32 Rules</li></ul><ul><li>16 Models</li></ul>](RM/r_m_rsa_rsa_netwitness_Privilege_Abuse.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                                                                                                                                                                     | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Create Account](https://attack.mitre.org/techniques/T1136)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |