Vendor: Johnson Controls
========================
Product: Johnson Controls P2000
-------------------------------
|                                 Use-Case                                  | Activity Types            | Event Types/Parsers                                                                                                | MITRE TTP                  | Content                   |
|:-------------------------------------------------------------------------:| ------------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------- |
| [Compromised Credentials](../UseCases/usecase_compromised_credentials.md) | - Activity Time  and Type |  physical-access<br> -- [p2000-physical-badge-access](../Parsers/parserContent_p2000-physical-badge-access.md)<br> | T1078 - Valid Accounts<br> |  - 1 Rules<br> - 1 Models |
|        [Lateral Movement](../UseCases/usecase_lateral_movement.md)        | - Badge Access            |  physical-access<br> -- [p2000-physical-badge-access](../Parsers/parserContent_p2000-physical-badge-access.md)<br> | T1078 - Valid Accounts<br> |  - 1 Rules<br>            |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilage escalation                                                | Defense evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |