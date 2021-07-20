Vendor: HP
==========
Product: Aruba ClearPass Access Control and Policy Management
-------------------------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   3    |     2      |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  computer-logon<br> ↳[q-aruba-nac-logon-2](Ps/pC_qarubanaclogon2.md)<br> ↳[q-aruba-nac-logon-1](Ps/pC_qarubanaclogon1.md)<br> ↳[q-aruba-nac-logon-4](Ps/pC_qarubanaclogon4.md)<br> ↳[q-aruba-nac-logon-3](Ps/pC_qarubanaclogon3.md)<br><br> nac-failed-logon<br> ↳[q-aruba-failed-nac-logon-1](Ps/pC_qarubafailednaclogon1.md)<br> ↳[l-aruba-failed-nac-logon](Ps/pC_larubafailednaclogon.md)<br> ↳[q-aruba-failed-nac-logon](Ps/pC_qarubafailednaclogon.md)<br> ↳[leef-aruba-nac-logon](Ps/pC_leefarubanaclogon.md)<br> ↳[cef-aruba-nac-logon-4](Ps/pC_cefarubanaclogon4.md)<br><br> nac-logon<br> ↳[cef-aruba-nac-logon-1](Ps/pC_cefarubanaclogon1.md)<br> ↳[l-aruba-nac-logon](Ps/pC_larubanaclogon.md)<br> ↳[q-aruba-nac-logon-2](Ps/pC_qarubanaclogon2.md)<br> ↳[q-aruba-nac-logon-1](Ps/pC_qarubanaclogon1.md)<br> ↳[q-aruba-nac-logon-4](Ps/pC_qarubanaclogon4.md)<br> ↳[q-aruba-nac-logon-3](Ps/pC_qarubanaclogon3.md)<br> ↳[leef-aruba-nac-logon](Ps/pC_leefarubanaclogon.md)<br> ↳[cef-aruba-nac-logon-4](Ps/pC_cefarubanaclogon4.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>4 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_hp_aruba_clearpass_access_control_and_policy_management_Abnormal_Authentication_&_Access.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement                                                     | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | -------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> |            |                     |              |        |