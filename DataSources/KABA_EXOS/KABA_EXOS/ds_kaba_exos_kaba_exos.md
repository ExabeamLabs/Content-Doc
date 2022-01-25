Vendor: KABA EXOS
=================
Product: KABA EXOS
------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  27   |   13   |     4      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  file-read<br> ↳[cef-kaba-badge-access](Ps/pC_cefkababadgeaccess.md)<br> | T1003.003 - T1003.003<br>T1083 - File and Directory Discovery<br> | [<ul><li>25 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_kaba_exos_kaba_exos_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  file-read<br> ↳[cef-kaba-badge-access](Ps/pC_cefkababadgeaccess.md)<br> | T1083 - File and Directory Discovery<br>    | [<ul><li>23 Rules</li></ul><ul><li>12 Models</li></ul>](RM/r_m_kaba_exos_kaba_exos_Data_Access.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  file-read<br> ↳[cef-kaba-badge-access](Ps/pC_cefkababadgeaccess.md)<br> | T1027 - Obfuscated Files or Information<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_kaba_exos_kaba_exos_Malware.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  file-read<br> ↳[cef-kaba-badge-access](Ps/pC_cefkababadgeaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_kaba_exos_kaba_exos_Privilege_Abuse.md)    |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  file-read<br> ↳[cef-kaba-badge-access](Ps/pC_cefkababadgeaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_kaba_exos_kaba_exos_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                                                                                                         | Credential Access                                                          | Discovery                                                                         | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  |            |                     |              |        |