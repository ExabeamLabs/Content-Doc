Vendor: AppSense Application Manager
====================================
Product: AppSense Application Manager
-------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  21   |   11   |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  process-alert<br> ↳[appsense-process-alert](Ps/pC_appsenseprocessalert.md)<br> ↳[leef-appsense-process-alert](Ps/pC_leefappsenseprocessalert.md)<br> | T1003 - OS Credential Dumping<br>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1204 - User Execution<br> | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_appsense_application_manager_appsense_application_manager_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  process-alert<br> ↳[appsense-process-alert](Ps/pC_appsenseprocessalert.md)<br> ↳[leef-appsense-process-alert](Ps/pC_leefappsenseprocessalert.md)<br> | T1204 - User Execution<br>    | [<ul><li>17 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_appsense_application_manager_appsense_application_manager_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access                                                          | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> |           |                  |            |                     |              |        |