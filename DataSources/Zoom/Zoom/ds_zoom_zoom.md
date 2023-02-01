Vendor: Zoom
============
Product: Zoom
-------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  11   |   5    |         3          |      4      |    4    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  webconference-login<br> ↳[zoom-login](Ps/pC_zoomlogin.md)<br>    | T1078.004 - Valid Accounts: Cloud Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_zoom_zoom_Ransomware.md)    |
| [Workforce Protection](../../../UseCases/uc_workforce_protection.md) |  web-meeting-started<br> ↳[zoom-meeting-started](Ps/pC_zoommeetingstarted.md)<br><br> web-meeting-updated<br> ↳[zoom-meeting-updated](Ps/pC_zoommeetingupdated.md)<br><br> webconference-login<br> ↳[zoom-login](Ps/pC_zoomlogin.md)<br><br> webconference-operations-activity<br> ↳[zoom-operations-activity](Ps/pC_zoomoperationsactivity.md)<br> | T1078.004 - Valid Accounts: Cloud Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1098 - Account Manipulation<br> | [<ul><li>11 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_zoom_zoom_Workforce_Protection.md) |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                             | Execution | Persistence                                                                                                                                  | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |