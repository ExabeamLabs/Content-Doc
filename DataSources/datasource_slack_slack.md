Vendor: Slack
=============
Product: Slack
--------------
|                                 Use-Case                                  | Activity Types             | Event Types/Parsers                                                                                                                                                                            | MITRE TTP                  | Content        |
|:-------------------------------------------------------------------------:| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | -------------- |
| [Compromised Credentials](../UseCases/usecase_compromised_credentials.md) | - Critical System Activity |  file-download<br> -- [slack-file-download](../Parsers/parserContent_slack-file-download.md)<br><br> file-upload<br> -- [slack-file-upload](../Parsers/parserContent_slack-file-upload.md)<br> | T1078 - Valid Accounts<br> |  - 1 Rules<br> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilage escalation                                                | Defense evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |