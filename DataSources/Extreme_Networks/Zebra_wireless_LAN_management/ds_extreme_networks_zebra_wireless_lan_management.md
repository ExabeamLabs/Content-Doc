Vendor: Extreme Networks
========================
Product: Zebra wireless LAN management
--------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-lockout<br> ↳[zebra-wlm-ssh-failed](Ps/pC_zebrawlmsshfailed.md)<br> | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_extreme_networks_zebra_wireless_lan_management_Abnormal_Authentication_&_Access.md) |
|    [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)    |  account-lockout<br> ↳[zebra-wlm-ssh-failed](Ps/pC_zebrawlmsshfailed.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_extreme_networks_zebra_wireless_lan_management_Brute_Force_Attack.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  account-lockout<br> ↳[zebra-wlm-ssh-failed](Ps/pC_zebrawlmsshfailed.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_extreme_networks_zebra_wireless_lan_management_Privilege_Escalation.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access                                                | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Brute Force](https://attack.mitre.org/techniques/T1110)<br><br> |           |                  |            |                     |              |        |