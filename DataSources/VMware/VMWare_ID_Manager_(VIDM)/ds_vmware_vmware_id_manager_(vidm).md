Vendor: VMware
==============
Product: VMWare ID Manager (VIDM)
---------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   4    |     3      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  privileged-object-access<br> ↳[vmware-id-manager-obj-access](Ps/pC_vmwareidmanagerobjaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_vmware_vmware_id_manager_(vidm)_Abnormal_Authentication_&_Access.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  privileged-object-access<br> ↳[vmware-id-manager-obj-access](Ps/pC_vmwareidmanagerobjaccess.md)<br> | T1204 - User Execution<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_vmware_vmware_id_manager_(vidm)_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  privileged-object-access<br> ↳[vmware-id-manager-obj-access](Ps/pC_vmwareidmanagerobjaccess.md)<br> |    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_vmware_vmware_id_manager_(vidm)_Other.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  privileged-object-access<br> ↳[vmware-id-manager-obj-access](Ps/pC_vmwareidmanagerobjaccess.md)<br> | T1059 - Command and Scripting Interperter<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_vmware_vmware_id_manager_(vidm)_Privileged_Activity.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution                                                                                                                                                 | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Command and Scripting Interperter](https://attack.mitre.org/techniques/T1059)<br><br>[User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |