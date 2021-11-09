Vendor: OneSpan
===============
Product: OneSpan
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   5    |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  authentication-successful<br> ↳[onespan-failed-logon](Ps/pC_onespanfailedlogon.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br> | [<ul><li>11 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_onespan_onespan_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  authentication-successful<br> ↳[onespan-failed-logon](Ps/pC_onespanfailedlogon.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br> | [<ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_onespan_onespan_Compromised_Credentials.md)    |
|    [Evasion](../../../UseCases/uc_evasion.md)    |  authentication-successful<br> ↳[onespan-failed-logon](Ps/pC_onespanfailedlogon.md)<br> | T1090.003 - Proxy: Multi-hop Proxy<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_onespan_onespan_Evasion.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  authentication-successful<br> ↳[onespan-failed-logon](Ps/pC_onespanfailedlogon.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_onespan_onespan_Malware.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  authentication-successful<br> ↳[onespan-failed-logon](Ps/pC_onespanfailedlogon.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_onespan_onespan_Ransomware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |