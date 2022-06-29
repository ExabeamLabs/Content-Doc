Vendor: FireEye
===============
Product: FireEye Email Threat Prevention (ETP)
----------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-email-alert-in<br> ↳[fireeye-dlp-email](Ps/pC_fireeyedlpemail.md)<br> ↳[fireeye-dlp-email-alert](Ps/pC_fireeyedlpemailalert.md)<br><br> dlp-email-alert-in-failed<br> ↳[fireeye-dlp-email](Ps/pC_fireeyedlpemail.md)<br> ↳[fireeye-dlp-email-alert](Ps/pC_fireeyedlpemailalert.md)<br> | T1190 - Exploit Public Fasing Application<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_fireeye_fireeye_email_threat_prevention_(etp)_Malware.md)    |
|     [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)     |  dlp-email-alert-in<br> ↳[fireeye-dlp-email](Ps/pC_fireeyedlpemail.md)<br> ↳[fireeye-dlp-email-alert](Ps/pC_fireeyedlpemailalert.md)<br><br> dlp-email-alert-in-failed<br> ↳[fireeye-dlp-email](Ps/pC_fireeyedlpemail.md)<br> ↳[fireeye-dlp-email-alert](Ps/pC_fireeyedlpemailalert.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_fireeye_fireeye_email_threat_prevention_(etp)_Privilege_Abuse.md)     |
| [Privileged Activity](../../../UseCases/uc_privileged_activity.md) |  dlp-email-alert-in<br> ↳[fireeye-dlp-email](Ps/pC_fireeyedlpemail.md)<br> ↳[fireeye-dlp-email-alert](Ps/pC_fireeyedlpemailalert.md)<br><br> dlp-email-alert-in-failed<br> ↳[fireeye-dlp-email](Ps/pC_fireeyedlpemail.md)<br> ↳[fireeye-dlp-email-alert](Ps/pC_fireeyedlpemailalert.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_fireeye_fireeye_email_threat_prevention_(etp)_Privileged_Activity.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                            | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |