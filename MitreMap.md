ATT&CK Matrix for Enterprise
============================
### MITRE Techniques:
### MITRE Sub-techniques:
| Initial Access                                                                                                                                                                                                           | Execution                                                                                                                                  | Persistence                                                                                                                                                                                                                                                                                      | Privilege Escalation                                                                                                                                                                                                                 | Defense Evasion                                                                                                                      | Credential Access                                                                                                                          | Discovery                                                                                                                                           | Lateral Movement                                                     | Collection                                                                              | Command and Control                                                                                                                                                                                                        | Exfiltration                                                                                                                                                                                                                                                       | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br> | [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br>[User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Masquerading](https://attack.mitre.org/techniques/T1036)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br>[Brute Force](https://attack.mitre.org/techniques/T1110)<br><br> | [Network Service Scanning](https://attack.mitre.org/techniques/T1046)<br><br>[Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Remote Access Software](https://attack.mitre.org/techniques/T1219)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |

| TTP   | Rules |
| ----- | ----- |
| T1003 | 1138  |
| T1102 | 828   |
| T1168 | 8     |
| T1048 | 9210  |
| T1188 | 6106  |
| T1068 | 2214  |
| T1189 | 326   |
| T1046 | 64    |
| T1021 | 6366  |
| T1043 | 64    |
| T1065 | 80    |
| T1087 | 160   |
| T1066 | 542   |
| T1041 | 176   |
| T1086 | 6     |
| T1208 | 5992  |
| T1204 | 7802  |
| T1036 | 672   |
| T1213 | 176   |
| T1078 | 37240 |
| T1133 | 5122  |
| T1035 | 6     |
| T1098 | 592   |
| T1110 | 970   |
| T1077 | 240   |
| T1052 | 776   |
| T1075 | 1830  |
| T1097 | 560   |
| T1053 | 68    |
| T1219 | 3216  |
| T1050 | 18    |
| T1071 | 8930  |