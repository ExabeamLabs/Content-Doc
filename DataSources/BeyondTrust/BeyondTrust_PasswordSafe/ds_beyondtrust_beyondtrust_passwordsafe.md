Vendor: BeyondTrust
===================
Product: BeyondTrust PasswordSafe
---------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  31   |   21   |     3      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-switch<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br><br> privileged-access<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_beyondtrust_beyondtrust_passwordsafe_Abnormal_Authentication_&_Access.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  account-switch<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br><br> privileged-access<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_beyondtrust_beyondtrust_passwordsafe_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  account-switch<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br><br> privileged-access<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>7 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_beyondtrust_beyondtrust_passwordsafe_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  account-switch<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br><br> privileged-access<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> | T1078 - Valid Accounts<br>T1555.005 - T1555.005<br> | [<ul><li>10 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_beyondtrust_beyondtrust_passwordsafe_Privilege_Escalation.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  account-switch<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br><br> privileged-access<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> | T1078 - Valid Accounts<br>TA0002 - TA0002<br>       | [<ul><li>11 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_beyondtrust_beyondtrust_passwordsafe_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access                                                                     | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)<br><br> |           |                  |            |                     |              |        |