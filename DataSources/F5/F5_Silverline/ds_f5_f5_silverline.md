Vendor: F5
==========
Product: F5 Silverline
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   8   |   0    |     4      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|        [Cryptomining](../../../UseCases/uc_cryptomining.md)        |  dlp-email-alert-in-failed<br> ↳[f5-silverline-network-alert-1](Ps/pC_f5silverlinenetworkalert1.md)<br><br> network-connection-failed<br> ↳[f5-silverline-waf](Ps/pC_f5silverlinewaf.md)<br> | T1496 - Resource Hijacking<br>         | [<ul><li>1 Rules</li></ul>](RM/r_m_f5_f5_silverline_Cryptomining.md)        |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  dlp-email-alert-in-failed<br> ↳[f5-silverline-network-alert-1](Ps/pC_f5silverlinenetworkalert1.md)<br><br> network-connection-failed<br> ↳[f5-silverline-waf](Ps/pC_f5silverlinewaf.md)<br> | TA0010 - TA0010<br>TA0011 - TA0011<br> | [<ul><li>6 Rules</li></ul>](RM/r_m_f5_f5_silverline_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-email-alert-in-failed<br> ↳[f5-silverline-network-alert-1](Ps/pC_f5silverlinenetworkalert1.md)<br><br> network-connection-failed<br> ↳[f5-silverline-waf](Ps/pC_f5silverlinewaf.md)<br> | TA0011 - TA0011<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_f5_f5_silverline_Malware.md)    |
|     [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)     |  dlp-email-alert-in-failed<br> ↳[f5-silverline-network-alert-1](Ps/pC_f5silverlinenetworkalert1.md)<br><br> network-connection-failed<br> ↳[f5-silverline-waf](Ps/pC_f5silverlinewaf.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_f5_f5_silverline_Privilege_Abuse.md)     |
| [Privileged Activity](../../../UseCases/uc_privileged_activity.md) |  dlp-email-alert-in-failed<br> ↳[f5-silverline-network-alert-1](Ps/pC_f5silverlinenetworkalert1.md)<br><br> network-connection-failed<br> ↳[f5-silverline-waf](Ps/pC_f5silverlinewaf.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_f5_f5_silverline_Privileged_Activity.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact                                                                  |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ----------------------------------------------------------------------- |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |