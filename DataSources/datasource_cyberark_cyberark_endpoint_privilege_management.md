Vendor: CyberArk
================
Product: CyberArk Endpoint Privilege Management
-----------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   2    |     2      |      1      |    1    |

|                                 Use-Case                                  | Activity Types                                               | Event Types/Parsers                                                                                                                              | MITRE TTP                  | Content                                             |
|:-------------------------------------------------------------------------:| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | --------------------------------------------------- |
| [Compromised Credentials](../UseCases/usecase_compromised_credentials.md) | <ul><li>Activity Time  and Type</li></ul>                    |  privileged-object-access<br> ↳ [json-cyberark-privileged-object-access](../Parsers/parserContent_json-cyberark-privileged-object-access.md)<br> | T1078 - Valid Accounts<br> | <ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul> |
|       [Malware Detection](../UseCases/usecase_malware_detection.md)       | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  privileged-object-access<br> ↳ [json-cyberark-privileged-object-access](../Parsers/parserContent_json-cyberark-privileged-object-access.md)<br> | T1204 - User Execution<br> | <ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul> |
|    [Ransomware Detection](../UseCases/usecase_ransomware_detection.md)    | <ul><li>Endpoint Activity</li><li>Process Activity</li></ul> |  privileged-object-access<br> ↳ [json-cyberark-privileged-object-access](../Parsers/parserContent_json-cyberark-privileged-object-access.md)<br> | T1204 - User Execution<br> | <ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                           | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |