Vendor: HP Aruba
================
Product: HP Aruba
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      3      |    3    |

|               Use-Case                | Activity Types                            | Event Types/Parsers                                                                                                                                                                                                                                                                                 | MITRE TTP                  | Content                                             |
|:-------------------------------------:| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Activity Time  and Type</li></ul> |  computer-logon<br> ↳ [aruba-nac-logon](../Parsers/parserContent_aruba-nac-logon.md)<br><br> nac-failed-logon<br> ↳ [cef-aruba-nac-failed-logon](../Parsers/parserContent_cef-aruba-nac-failed-logon.md)<br><br> nac-logon<br> ↳ [aruba-nac-logon](../Parsers/parserContent_aruba-nac-logon.md)<br> | T1078 - Valid Accounts<br> | <ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |