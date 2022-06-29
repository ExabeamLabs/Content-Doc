Vendor: AMAG
============
Product: Symmetry Access Control
--------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  12   |   6    |     1      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  failed-physical-access<br> ↳[s-amag-badge-access](Ps/pC_samagbadgeaccess.md)<br> ↳[cef-amag-badge-access-failed-3](Ps/pC_cefamagbadgeaccessfailed3.md)<br> ↳[cef-amag-badge-access-failed-1](Ps/pC_cefamagbadgeaccessfailed1.md)<br> ↳[cef-amag-badge-access-failed-2](Ps/pC_cefamagbadgeaccessfailed2.md)<br> ↳[amag-badge-access](Ps/pC_amagbadgeaccess.md)<br><br> physical-access<br> ↳[s-amag-badge-access](Ps/pC_samagbadgeaccess.md)<br> ↳[cef-amag-badge-access-2](Ps/pC_cefamagbadgeaccess2.md)<br> ↳[cef-amag-badge-access-1](Ps/pC_cefamagbadgeaccess1.md)<br> ↳[amag-badge-access](Ps/pC_amagbadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_amag_symmetry_access_control_Abnormal_Authentication_&_Access.md) |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  failed-physical-access<br> ↳[s-amag-badge-access](Ps/pC_samagbadgeaccess.md)<br> ↳[cef-amag-badge-access-failed-3](Ps/pC_cefamagbadgeaccessfailed3.md)<br> ↳[cef-amag-badge-access-failed-1](Ps/pC_cefamagbadgeaccessfailed1.md)<br> ↳[cef-amag-badge-access-failed-2](Ps/pC_cefamagbadgeaccessfailed2.md)<br> ↳[amag-badge-access](Ps/pC_amagbadgeaccess.md)<br><br> physical-access<br> ↳[s-amag-badge-access](Ps/pC_samagbadgeaccess.md)<br> ↳[cef-amag-badge-access-2](Ps/pC_cefamagbadgeaccess2.md)<br> ↳[cef-amag-badge-access-1](Ps/pC_cefamagbadgeaccess1.md)<br> ↳[amag-badge-access](Ps/pC_amagbadgeaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>9 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_amag_symmetry_access_control_Physical_Security.md)    |
[Next Page -->>](2_ds_amag_symmetry_access_control.md)

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |