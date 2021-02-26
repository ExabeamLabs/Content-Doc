Vendor: SafeSend
================
Product: SafeSend
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  33   |   15   |     2      |      1      |    1    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                              | MITRE TTP                                          | Content                                                                                                          |
|:--------------------------------------------------------------------------:| ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  dlp-email-alert-out<br> ↳ [s-safesend-dlp-email-alert](Parsers/parserContent_s-safesend-dlp-email-alert.md)<br> | T1078 - Valid Accounts<br>                         | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_safesend_safesend_Compromised_Credentials.md)                       |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  dlp-email-alert-out<br> ↳ [s-safesend-dlp-email-alert](Parsers/parserContent_s-safesend-dlp-email-alert.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br> | [<ul><li>32 Rules</li></ul><ul><li>15 Models</li></ul>](Rules_Models/r_m_safesend_safesend_Data_Exfiltration.md) |
|                [Phishing](../../../UseCases/uc_phishing.md)                |  dlp-email-alert-out<br> ↳ [s-safesend-dlp-email-alert](Parsers/parserContent_s-safesend-dlp-email-alert.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br> | [<ul><li>7 Rules</li></ul><ul><li>4 Models</li></ul>](Rules_Models/r_m_safesend_safesend_Phishing.md)            |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------- | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br> |        |