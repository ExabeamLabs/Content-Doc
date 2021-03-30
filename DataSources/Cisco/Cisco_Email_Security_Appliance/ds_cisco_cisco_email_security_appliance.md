Vendor: Cisco
=============
Product: Cisco Email Security Appliance
---------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  36   |   15   |     2      |      2      |    2    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                     | MITRE TTP                                                                    | Content                                                                                                                 |
|:--------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  dlp-email-alert-in<br> ↳ [cisco-esa-dlp-alert](Parsers/parserContent_cisco-esa-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cisco-esa-dlp-alert](Parsers/parserContent_cisco-esa-dlp-alert.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1078 - Valid Accounts<br> | [<ul><li>36 Rules</li></ul><ul><li>15 Models</li></ul>](Rules_Models/r_m_cisco_cisco_email_security_appliance_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------- | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |