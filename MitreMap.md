ATT&CK Matrix for Enterprise
============================
### MITRE Techniques: 37
### MITRE Sub-techniques: 0
| Initial Access                                                                                                                                                                                                           | Execution                                                                                                                                  | Persistence                                                                                                                                                                                                                                                                                      | Privilege Escalation                                                                                                                                                                                                                 | Defense Evasion                                                                                                                                                                                                    | Credential Access                                                                                                                          | Discovery                                                                                                                                                                                                                                                                                                                                                                                                       | Lateral Movement                                                     | Collection                                                                              | Command and Control                                                                                                                                                                                                        | Exfiltration                                                                                                                                                                                                                                                       | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br> | [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br>[User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Masquerading](https://attack.mitre.org/techniques/T1036)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br>[Brute Force](https://attack.mitre.org/techniques/T1110)<br><br> | [Network Service Scanning](https://attack.mitre.org/techniques/T1046)<br><br>[Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br>[File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br>[System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)<br><br>[System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Remote Access Software](https://attack.mitre.org/techniques/T1219)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |

| TTP   | Rules |
| ----- | ----- |
| T1003 | 7     |
| T1016 | 5     |
| T1021 | 17    |
| T1033 | 1     |
| T1035 | 1     |
| T1036 | 4     |
| T1041 | 1     |
| T1043 | 4     |
| T1046 | 4     |
| T1048 | 65    |
| T1050 | 7     |
| T1052 | 8     |
| T1053 | 11    |
| T1065 | 13    |
| T1066 | 8     |
| T1068 | 17    |
| T1070 | 1     |
| T1071 | 55    |
| T1075 | 6     |
| T1076 | 1     |
| T1077 | 8     |
| T1078 | 103   |
| T1083 | 3     |
| T1086 | 2     |
| T1087 | 2     |
| T1097 | 3     |
| T1098 | 15    |
| T1102 | 3     |
| T1110 | 11    |
| T1133 | 8     |
| T1168 | 1     |
| T1188 | 8     |
| T1189 | 1     |
| T1204 | 13    |
| T1208 | 13    |
| T1213 | 1     |
| T1219 | 24    |