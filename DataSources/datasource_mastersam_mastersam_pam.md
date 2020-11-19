Vendor: MasterSAM
=================
Product: MasterSAM PAM
----------------------
|                                 Use-Case                                  | Activity Types            | Event Types/Parsers                                                                                                            | MITRE TTP                  | Content                   |
|:-------------------------------------------------------------------------:| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------- |
| [Compromised Credentials](../UseCases/usecase_compromised_credentials.md) | - Activity Time  and Type |  account-password-change<br> -- [mastersam-pam-password-change](../Parsers/parserContent_mastersam-pam-password-change.md)<br> | T1078 - Valid Accounts<br> |  - 1 Rules<br> - 1 Models |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilage escalation                                                | Defense evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |