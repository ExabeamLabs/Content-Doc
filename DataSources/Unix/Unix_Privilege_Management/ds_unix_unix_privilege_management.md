Vendor: Unix
============
Product: Unix Privilege Management
----------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  32   |   19   |     6      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  dlp-alert<br> ↳[upm-account-switch](Ps/pC_upmaccountswitch.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br> | [<ul><li>29 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_unix_unix_privilege_management_Data_Exfiltration.md)  |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  dlp-alert<br> ↳[upm-account-switch](Ps/pC_upmaccountswitch.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br> | [<ul><li>29 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_unix_unix_privilege_management_Data_Leak.md)          |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-alert<br> ↳[upm-account-switch](Ps/pC_upmaccountswitch.md)<br> | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_unix_unix_privilege_management_Malware.md)    |
| [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md) |  dlp-alert<br> ↳[upm-account-switch](Ps/pC_upmaccountswitch.md)<br> | T1021.002 - Remote Services: SMB/Windows Admin Shares<br>T1087 - Account Discovery<br>      | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_unix_unix_privilege_management_Privilege_Escalation.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery                                                              | Lateral Movement                                                                                                                                                       | Collection | Command and Control                                                             | Exfiltration                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   | [Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)<br><br> |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |