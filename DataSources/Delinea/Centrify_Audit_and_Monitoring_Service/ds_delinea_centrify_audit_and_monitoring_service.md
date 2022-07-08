Vendor: Delinea
===============
Product: Centrify Audit and Monitoring Service
----------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  48   |   19   |     12     |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  file-delete<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-read<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-write<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br> | T1003.001 - T1003.001<br>T1003.002 - T1003.002<br>T1003.003 - T1003.003<br>T1083 - File and Directory Discovery<br>       | [<ul><li>33 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_delinea_centrify_audit_and_monitoring_service_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  file-delete<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-read<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-write<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br> | T1083 - File and Directory Discovery<br>    | [<ul><li>24 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_delinea_centrify_audit_and_monitoring_service_Data_Access.md)    |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  file-delete<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-read<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-write<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br> | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_delinea_centrify_audit_and_monitoring_service_Data_Exfiltration.md)         |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  file-delete<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-read<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-write<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br> | T1114.001 - T1114.001<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_delinea_centrify_audit_and_monitoring_service_Data_Leak.md)    |
|     [Destruction of Data](../../../UseCases/uc_destruction_of_data.md)     |  file-delete<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-read<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-write<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br> | T1070.004 - Indicator Removal on Host: File Deletion<br>T1485 - Data Destruction<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_delinea_centrify_audit_and_monitoring_service_Destruction_of_Data.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  file-delete<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-read<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-write<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br> | T1003.002 - T1003.002<br>T1505.003 - Server Software Component: Web Shell<br>T1547.001 - T1547.001<br>TA0002 - TA0002<br> | [<ul><li>11 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_delinea_centrify_audit_and_monitoring_service_Malware.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  file-delete<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-read<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-write<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_delinea_centrify_audit_and_monitoring_service_Privilege_Abuse.md)    |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  file-delete<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-read<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-write<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_delinea_centrify_audit_and_monitoring_service_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  file-delete<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-read<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br><br> file-write<br> ↳[centrify-file-access](Ps/pC_centrifyfileaccess.md)<br> | T1486 - Data Encrypted for Impact<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_delinea_centrify_audit_and_monitoring_service_Ransomware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                      | Execution | Persistence                                                                                                                                                                                                                                                                                                                          | Privilege Escalation                                                                                                                                      | Defense Evasion                                                                                                                                                                                                                                    | Credential Access                                                          | Discovery                                                                         | Lateral Movement | Collection                                                            | Command and Control | Exfiltration | Impact                                                                                                                                              |
| ------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------- | --------------------------------------------------------------------- | ------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003)<br><br>[Server Software Component](https://attack.mitre.org/techniques/T1505)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br> |                     |              | [Data Destruction](https://attack.mitre.org/techniques/T1485)<br><br>[Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)<br><br> |