Vendor: Forcepoint
==================
Product: Forcepoint Insider Threat
----------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   0    |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  failed-vpn-login<br> ↳[cef-forcepoint-it-dlp-alert](Ps/pC_cefforcepointitdlpalert.md)<br> | T1133 - External Remote Services<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_forcepoint_forcepoint_insider_threat_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  failed-vpn-login<br> ↳[cef-forcepoint-it-dlp-alert](Ps/pC_cefforcepointitdlpalert.md)<br> | T1133 - External Remote Services<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_forcepoint_forcepoint_insider_threat_Compromised_Credentials.md)          |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  failed-vpn-login<br> ↳[cef-forcepoint-it-dlp-alert](Ps/pC_cefforcepointitdlpalert.md)<br> | T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_forcepoint_forcepoint_insider_threat_Lateral_Movement.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  failed-vpn-login<br> ↳[cef-forcepoint-it-dlp-alert](Ps/pC_cefforcepointitdlpalert.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_forcepoint_forcepoint_insider_threat_Ransomware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |