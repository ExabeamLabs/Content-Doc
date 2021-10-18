Vendor: Specops
===============
Product: Specops Password Reset
-------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-password-reset<br> ↳[specops-account-password-reset](Ps/pC_specopsaccountpasswordreset.md)<br><br> account-unlocked<br> ↳[specops-account-unlocked](Ps/pC_specopsaccountunlocked.md)<br> | T1078 - Valid Accounts<br>       | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_specops_specops_password_reset_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  account-password-reset<br> ↳[specops-account-password-reset](Ps/pC_specopsaccountpasswordreset.md)<br><br> account-unlocked<br> ↳[specops-account-unlocked](Ps/pC_specopsaccountunlocked.md)<br> | T1098 - Account Manipulation<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_specops_specops_password_reset_Account_Manipulation.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  account-password-reset<br> ↳[specops-account-password-reset](Ps/pC_specopsaccountpasswordreset.md)<br><br> account-unlocked<br> ↳[specops-account-unlocked](Ps/pC_specopsaccountunlocked.md)<br> | T1098 - Account Manipulation<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_specops_specops_password_reset_Privilege_Abuse.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                                                                                                  | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |