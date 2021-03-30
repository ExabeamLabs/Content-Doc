ATT&CK Matrix for Enterprise
============================
### MITRE Techniques: 32
### MITRE Sub-techniques: 0
| Initial Access                                                                                                                                                                                                           | Execution                                                                                                                                  | Persistence                                                                                                                                                                                                                                                                                      | Privilege Escalation                                                                                                                                                                                                                 | Defense Evasion                                                                                                                      | Credential Access                                                                                                                          | Discovery                                                                                                                                           | Lateral Movement                                                     | Collection                                                                              | Command and Control                                                                                                                                                                                                        | Exfiltration                                                                                                                                                                                                                                                       | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br> | [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br>[User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Masquerading](https://attack.mitre.org/techniques/T1036)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br>[Brute Force](https://attack.mitre.org/techniques/T1110)<br><br> | [Network Service Scanning](https://attack.mitre.org/techniques/T1046)<br><br>[Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Remote Access Software](https://attack.mitre.org/techniques/T1219)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |

| TTP   | Rules |
| ----- | ----- |
| T1003 | 5     |
| T1021 | 13    |
| T1035 | 1     |
| T1036 | 4     |
| T1041 | 1     |
| T1043 | 4     |
| T1046 | 4     |
| T1048 | 57    |
| T1050 | 3     |
| T1052 | 8     |
| T1053 | 7     |
| T1065 | 5     |
| T1066 | 1     |
| T1068 | 7     |
| T1071 | 32    |
| T1075 | 5     |
| T1077 | 6     |
| T1078 | 88    |
| T1086 | 1     |
| T1087 | 3     |
| T1097 | 3     |
| T1098 | 6     |
| T1102 | 3     |
| T1110 | 7     |
| T1133 | 7     |
| T1168 | 1     |
| T1188 | 8     |
| T1189 | 1     |
| T1204 | 8     |
| T1208 | 10    |
| T1213 | 1     |
| T1219 | 24    |