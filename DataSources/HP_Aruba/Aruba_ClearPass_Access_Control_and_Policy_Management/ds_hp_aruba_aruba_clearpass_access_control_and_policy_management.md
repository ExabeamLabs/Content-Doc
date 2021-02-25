Vendor: HP Aruba
================
Product: Aruba ClearPass Access Control and Policy Management
-------------------------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   3    |     2      |      1      |    1    |

|                                  Use-Case                                  | Event Types/Parsers                                                                          | MITRE TTP                                             | Content                                                                                                                                                          |
|:--------------------------------------------------------------------------:| -------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  nac-logon<br> ↳ [cef-aruba-nac-logon-1](Parsers/parserContent_cef-aruba-nac-logon-1.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>4 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_hp_aruba_aruba_clearpass_access_control_and_policy_management_Compromised_Credentials.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement                                                     | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | -------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> |            |                     |              |        |