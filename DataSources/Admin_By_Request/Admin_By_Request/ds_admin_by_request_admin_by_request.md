Vendor: Admin By Request
========================
Product: Admin By Request
-------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  20   |   15   |         2          |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP          | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  privileged-access<br> ↳[adminbyrequest-privileged-access](Ps/pC_adminbyrequestprivilegedaccess.md)<br><br> privileged-object-access<br> ↳[adminbyrequest-privileged-object-access](Ps/pC_adminbyrequestprivilegedobjectaccess.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_admin_by_request_admin_by_request_Abnormal_Authentication_&_Access.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  privileged-access<br> ↳[adminbyrequest-privileged-access](Ps/pC_adminbyrequestprivilegedaccess.md)<br><br> privileged-object-access<br> ↳[adminbyrequest-privileged-object-access](Ps/pC_adminbyrequestprivilegedobjectaccess.md)<br> | TA0002 - TA0002<br>        | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_admin_by_request_admin_by_request_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  privileged-access<br> ↳[adminbyrequest-privileged-access](Ps/pC_adminbyrequestprivilegedaccess.md)<br>    | T1078 - Valid Accounts<br> | [<ul><li>5 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_admin_by_request_admin_by_request_Privilege_Abuse.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  privileged-access<br> ↳[adminbyrequest-privileged-access](Ps/pC_adminbyrequestprivilegedaccess.md)<br>    | TA0002 - TA0002<br>        | [<ul><li>10 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_admin_by_request_admin_by_request_Privileged_Activity.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |