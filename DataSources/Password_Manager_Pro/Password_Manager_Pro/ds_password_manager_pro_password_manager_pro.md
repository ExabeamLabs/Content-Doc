Vendor: Password Manager Pro
============================
Product: Password Manager Pro
-----------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  17   |   9    |         4          |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-password-change<br> ↳[pmp-password-change](Ps/pC_pmppasswordchange.md)<br><br> account-switch<br> ↳[pmp-account-switch](Ps/pC_pmpaccountswitch.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_password_manager_pro_password_manager_pro_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  account-password-change<br> ↳[pmp-password-change](Ps/pC_pmppasswordchange.md)<br>    | T1098 - Account Manipulation<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_password_manager_pro_password_manager_pro_Account_Manipulation.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  account-switch<br> ↳[pmp-account-switch](Ps/pC_pmpaccountswitch.md)<br>    | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_password_manager_pro_password_manager_pro_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  account-password-change<br> ↳[pmp-password-change](Ps/pC_pmppasswordchange.md)<br><br> account-switch<br> ↳[pmp-account-switch](Ps/pC_pmpaccountswitch.md)<br> | T1078 - Valid Accounts<br>T1098 - Account Manipulation<br> | [<ul><li>3 Rules</li></ul>](RM/r_m_password_manager_pro_password_manager_pro_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  account-switch<br> ↳[pmp-account-switch](Ps/pC_pmpaccountswitch.md)<br>    | T1078 - Valid Accounts<br>T1555.005 - T1555.005<br>        | [<ul><li>10 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_password_manager_pro_password_manager_pro_Privilege_Escalation.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  account-switch<br> ↳[pmp-account-switch](Ps/pC_pmpaccountswitch.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_password_manager_pro_password_manager_pro_Privileged_Activity.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                      | Execution | Persistence                                                                                                                                  | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access                                                                     | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)<br><br> |           |                  |            |                     |              |        |