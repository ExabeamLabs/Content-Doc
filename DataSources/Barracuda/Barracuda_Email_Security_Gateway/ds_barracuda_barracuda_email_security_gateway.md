Vendor: Barracuda
=================
Product: Barracuda Email Security Gateway
-----------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      1      |    1    |

|                                  Use-Case                                  | Event Types/Parsers                                                                       | MITRE TTP                  | Content                                                                                                             |
|:--------------------------------------------------------------------------:| ----------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  dlp-email-alert-in<br> ↳ [barracuda-email](Parsers/parserContent_barracuda-email.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_barracuda_barracuda_email_security_gateway_Compromised_Credentials.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |