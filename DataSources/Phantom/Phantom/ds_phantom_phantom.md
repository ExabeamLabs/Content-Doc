Vendor: Phantom
===============
Product: Phantom
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  24   |   0    |     4      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  security-alert<br> ↳[s-phantom-dlp-email-in](Ps/pC_sphantomdlpemailin.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1078 - Valid Accounts<br> | [<ul><li>18 Rules</li></ul>](RM/r_m_phantom_phantom_Compromised_Credentials.md) |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  security-alert<br> ↳[s-phantom-dlp-email-in](Ps/pC_sphantomdlpemailin.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_phantom_phantom_Lateral_Movement.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  security-alert<br> ↳[s-phantom-dlp-email-in](Ps/pC_sphantomdlpemailin.md)<br> | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_phantom_phantom_Malware.md)    |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  security-alert<br> ↳[s-phantom-dlp-email-in](Ps/pC_sphantomdlpemailin.md)<br> | T1068 - Exploitation for Privilege Escalation<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_phantom_phantom_Privileged_Activity.md)      |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                                                                                                          | Defense Evasion                                                                                                                                                                                                                                                               | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     |              |        |