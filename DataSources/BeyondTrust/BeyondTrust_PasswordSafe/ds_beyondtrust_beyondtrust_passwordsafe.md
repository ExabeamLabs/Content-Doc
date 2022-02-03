Vendor: BeyondTrust
===================
Product: BeyondTrust PasswordSafe
---------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  20   |   15   |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  privileged-access<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_beyondtrust_beyondtrust_passwordsafe_Abnormal_Authentication_&_Access.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  privileged-access<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> | TA0002 - TA0002<br>        | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_beyondtrust_beyondtrust_passwordsafe_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  privileged-access<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>5 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_beyondtrust_beyondtrust_passwordsafe_Privilege_Abuse.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  privileged-access<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> ↳[beyondtrust-passwordsafe](Ps/pC_beyondtrustpasswordsafe.md)<br> | TA0002 - TA0002<br>        | [<ul><li>10 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_beyondtrust_beyondtrust_passwordsafe_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |