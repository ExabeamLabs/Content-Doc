Vendor: Endgame
===============
Product: Endgame EDR
--------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   2    |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  print-activity<br> ↳[endgame-edr-security-alert](Ps/pC_endgameedrsecurityalert.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_endgame_endgame_edr_Abnormal_Authentication_&_Access.md)    |
|    [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)    |  print-activity<br> ↳[endgame-edr-security-alert](Ps/pC_endgameedrsecurityalert.md)<br> | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_endgame_endgame_edr_Brute_Force_Attack.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  print-activity<br> ↳[endgame-edr-security-alert](Ps/pC_endgameedrsecurityalert.md)<br> | T1052 - Exfiltration Over Physical Medium<br> | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_endgame_endgame_edr_Data_Leak.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access                                                | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                           | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------- | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Brute Force](https://attack.mitre.org/techniques/T1110)<br><br> |           |                  |            |                     | [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |