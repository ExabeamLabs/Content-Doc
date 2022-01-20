Vendor: Mvision
===============
Product: Mvision
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-email-alert-in<br> ↳[s-mvision-dlp-alert](Ps/pC_smvisiondlpalert.md)<br> ↳[s-mvision-dlp-alert-1](Ps/pC_smvisiondlpalert1.md)<br> ↳[s-mvision-dlp-alert-3](Ps/pC_smvisiondlpalert3.md)<br> ↳[s-mvision-dlp-alert-2](Ps/pC_smvisiondlpalert2.md)<br> ↳[s-mvision-dlp-alert-5](Ps/pC_smvisiondlpalert5.md)<br> ↳[s-mvision-dlp-alert-4](Ps/pC_smvisiondlpalert4.md)<br> | T1190 - Exploit Public Fasing Application<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_mvision_mvision_Malware.md)    |
|     [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)     |  dlp-email-alert-in<br> ↳[s-mvision-dlp-alert](Ps/pC_smvisiondlpalert.md)<br> ↳[s-mvision-dlp-alert-1](Ps/pC_smvisiondlpalert1.md)<br> ↳[s-mvision-dlp-alert-3](Ps/pC_smvisiondlpalert3.md)<br> ↳[s-mvision-dlp-alert-2](Ps/pC_smvisiondlpalert2.md)<br> ↳[s-mvision-dlp-alert-5](Ps/pC_smvisiondlpalert5.md)<br> ↳[s-mvision-dlp-alert-4](Ps/pC_smvisiondlpalert4.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_mvision_mvision_Privilege_Abuse.md)     |
| [Privileged Activity](../../../UseCases/uc_privileged_activity.md) |  dlp-email-alert-in<br> ↳[s-mvision-dlp-alert](Ps/pC_smvisiondlpalert.md)<br> ↳[s-mvision-dlp-alert-1](Ps/pC_smvisiondlpalert1.md)<br> ↳[s-mvision-dlp-alert-3](Ps/pC_smvisiondlpalert3.md)<br> ↳[s-mvision-dlp-alert-2](Ps/pC_smvisiondlpalert2.md)<br> ↳[s-mvision-dlp-alert-5](Ps/pC_smvisiondlpalert5.md)<br> ↳[s-mvision-dlp-alert-4](Ps/pC_smvisiondlpalert4.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_mvision_mvision_Privileged_Activity.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                            | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |