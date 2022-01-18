Vendor: Microsoft
=================
Product: Microsoft NPS
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  14   |   6    |     2      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  nac-failed-logon<br> ↳[msnetwork-nac-logon](Ps/pC_msnetworknaclogon.md)<br> ↳[msnetwork-nac-logon-2](Ps/pC_msnetworknaclogon2.md)<br> ↳[cef-msn-nac-logon](Ps/pC_cefmsnnaclogon.md)<br> ↳[msnetwork-nac-logon-3](Ps/pC_msnetworknaclogon3.md)<br> ↳[msnetwork-nac-logon-4](Ps/pC_msnetworknaclogon4.md)<br> ↳[msnetwork-nac-logon-5](Ps/pC_msnetworknaclogon5.md)<br><br> nac-logon<br> ↳[microsoft-nps-nac-logon](Ps/pC_microsoftnpsnaclogon.md)<br> ↳[microsoft-nps-6278](Ps/pC_microsoftnps6278.md)<br> ↳[microsoft-npc-nac-logon-1](Ps/pC_microsoftnpcnaclogon1.md)<br> ↳[microsoft-nps-6272](Ps/pC_microsoftnps6272.md)<br> ↳[microsoft-npc-failed-logon-1](Ps/pC_microsoftnpcfailedlogon1.md)<br> ↳[microsoft-nps-6274](Ps/pC_microsoftnps6274.md)<br> ↳[microsoft-nps-6273](Ps/pC_microsoftnps6273.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br> | [<ul><li>14 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_microsoft_microsoft_nps_Abnormal_Authentication_&_Access.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement                                                     | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | -------------------------------------------------------------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> |            |                     |              |        |