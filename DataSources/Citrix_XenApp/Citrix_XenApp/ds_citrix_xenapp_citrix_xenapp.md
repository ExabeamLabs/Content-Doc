Vendor: Citrix XenApp
=====================
Product: Citrix XenApp
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  27   |   14   |     3      |      1      |    1    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                      | MITRE TTP                                                      | Content                                                                                                                          |
|:--------------------------------------------------------------------------:| -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  app-login<br> ↳ [cef-citrix-xenapp-app-login](Parsers/parserContent_cef-citrix-xenapp-app-login.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br> | [<ul><li>22 Rules</li></ul><ul><li>12 Models</li></ul>](Rules_Models/r_m_citrix_xenapp_citrix_xenapp_Compromised_Credentials.md) |
|          [Internal Fraud](../../../UseCases/uc_internal_fraud.md)          |  app-login<br> ↳ [cef-citrix-xenapp-app-login](Parsers/parserContent_cef-citrix-xenapp-app-login.md)<br> | T1078 - Valid Accounts<br>                                     | [<ul><li>4 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_citrix_xenapp_citrix_xenapp_Internal_Fraud.md)            |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  app-login<br> ↳ [cef-citrix-xenapp-app-login](Parsers/parserContent_cef-citrix-xenapp-app-login.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br> | [<ul><li>3 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_citrix_xenapp_citrix_xenapp_Lateral_Movement.md)          |
|       [Malware Detection](../../../UseCases/uc_malware_detection.md)       |  app-login<br> ↳ [cef-citrix-xenapp-app-login](Parsers/parserContent_cef-citrix-xenapp-app-login.md)<br> | T1188 - T1188<br>                                              | [<ul><li>3 Rules</li></ul>](Rules_Models/r_m_citrix_xenapp_citrix_xenapp_Malware_Detection.md)                                   |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  app-login<br> ↳ [cef-citrix-xenapp-app-login](Parsers/parserContent_cef-citrix-xenapp-app-login.md)<br> | T1078 - Valid Accounts<br>                                     | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_citrix_xenapp_citrix_xenapp_Privileged_Activity.md)                                 |
|    [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md)    |  app-login<br> ↳ [cef-citrix-xenapp-app-login](Parsers/parserContent_cef-citrix-xenapp-app-login.md)<br> | T1188 - T1188<br>                                              | [<ul><li>3 Rules</li></ul>](Rules_Models/r_m_citrix_xenapp_citrix_xenapp_Ransomware_Detection.md)                                |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |