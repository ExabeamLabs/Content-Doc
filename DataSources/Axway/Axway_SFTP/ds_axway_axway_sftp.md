Vendor: Axway
=============
Product: Axway SFTP
-------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   2    |     3      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  file-upload<br> ↳[axway-remote-logon](Ps/pC_axwayremotelogon.md)<br><br> process-network-failed<br> ↳[axway-sftp-file-upload](Ps/pC_axwaysftpfileupload.md)<br> | T1090.003 - Proxy: Multi-hop Proxy<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_axway_axway_sftp_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  file-upload<br> ↳[axway-remote-logon](Ps/pC_axwayremotelogon.md)<br><br> process-network-failed<br> ↳[axway-sftp-file-upload](Ps/pC_axwaysftpfileupload.md)<br> | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_axway_axway_sftp_Malware.md) |
|     [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)     |  file-upload<br> ↳[axway-remote-logon](Ps/pC_axwayremotelogon.md)<br><br> process-network-failed<br> ↳[axway-sftp-file-upload](Ps/pC_axwaysftpfileupload.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_axway_axway_sftp_Privilege_Abuse.md)    |
| [Privileged Activity](../../../UseCases/uc_privileged_activity.md) |  file-upload<br> ↳[axway-remote-logon](Ps/pC_axwayremotelogon.md)<br><br> process-network-failed<br> ↳[axway-sftp-file-upload](Ps/pC_axwaysftpfileupload.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_axway_axway_sftp_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |