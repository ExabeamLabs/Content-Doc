Vendor: Trend Micro
===================
Product: Deep Discovery Email Inspector
---------------------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   2   |   0    |         2          |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-email-alert-in<br> ↳[cef-trendmicro-dlp](Ps/pC_ceftrendmicrodlp.md)<br> ↳[cef-trendmicro-dlp-email-alert-in](Ps/pC_ceftrendmicrodlpemailalertin.md)<br> | T1190 - Exploit Public Fasing Application<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_trend_micro_deep_discovery_email_inspector_Malware.md)    |
|     [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)     |  dlp-email-alert-in<br> ↳[cef-trendmicro-dlp](Ps/pC_ceftrendmicrodlp.md)<br> ↳[cef-trendmicro-dlp-email-alert-in](Ps/pC_ceftrendmicrodlpemailalertin.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_trend_micro_deep_discovery_email_inspector_Privilege_Abuse.md)     |
| [Privileged Activity](../../../UseCases/uc_privileged_activity.md) |  dlp-email-alert-in<br> ↳[cef-trendmicro-dlp](Ps/pC_ceftrendmicrodlp.md)<br> ↳[cef-trendmicro-dlp-email-alert-in](Ps/pC_ceftrendmicrodlpemailalertin.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_trend_micro_deep_discovery_email_inspector_Privileged_Activity.md) |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                            | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |