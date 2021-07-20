Vendor: Siemens
===============
Product: Siemens
----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  failed-physical-access<br> ↳[r-syslog-physical-badge-access](Ps/pC_rsyslogphysicalbadgeaccess.md)<br> ↳[physical-badge-access-3](Ps/pC_physicalbadgeaccess3.md)<br><br> physical-access<br> ↳[r-syslog-physical-badge-access](Ps/pC_rsyslogphysicalbadgeaccess.md)<br> ↳[physical-badge-access-3](Ps/pC_physicalbadgeaccess3.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_siemens_siemens_Abnormal_Authentication_&_Access.md) |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  failed-physical-access<br> ↳[r-syslog-physical-badge-access](Ps/pC_rsyslogphysicalbadgeaccess.md)<br> ↳[physical-badge-access-3](Ps/pC_physicalbadgeaccess3.md)<br><br> physical-access<br> ↳[r-syslog-physical-badge-access](Ps/pC_rsyslogphysicalbadgeaccess.md)<br> ↳[physical-badge-access-3](Ps/pC_physicalbadgeaccess3.md)<br> | T1078 - Valid Accounts<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_siemens_siemens_Physical_Security.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            |                     |              |        |