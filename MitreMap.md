ATT&CK Matrix for Enterprise
============================
### MITRE Techniques: 65
### MITRE Sub-techniques: 0
| Initial Access                                                                                                                                                                                                           | Execution                                                                                                                                                                                                                         | Persistence                                                                                                                                                                                                                                                                                                                                                         | Privilege Escalation                                                                                                                                                                                                                                                                                                                                                                     | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Credential Access                                                                                                                                                                                               | Discovery                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Lateral Movement                                                                                                                                               | Collection                                                                              | Command and Control                                                                                                                                                                                                                                                                                  | Exfiltration                                                                                                                                                                                                                                                       | Impact                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br> | [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br>[User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Create Account](https://attack.mitre.org/techniques/T1136)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Access Token Manipulation](https://attack.mitre.org/techniques/T1134)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br>[Process Injection](https://attack.mitre.org/techniques/T1055)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Indirect Command Execution](https://attack.mitre.org/techniques/T1202)<br><br>[Impair Defenses](https://attack.mitre.org/techniques/T1562)<br><br>[Rogue Domain Controller](https://attack.mitre.org/techniques/T1207)<br><br>[Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127)<br><br>[Masquerading](https://attack.mitre.org/techniques/T1036)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)<br><br>[File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222)<br><br>[Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br>[Access Token Manipulation](https://attack.mitre.org/techniques/T1134)<br><br>[Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211)<br><br>[Process Injection](https://attack.mitre.org/techniques/T1055)<br><br>[Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br>[Brute Force](https://attack.mitre.org/techniques/T1110)<br><br>[Network Sniffing](https://attack.mitre.org/techniques/T1040)<br><br> | [Network Service Scanning](https://attack.mitre.org/techniques/T1046)<br><br>[Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br>[File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br>[Network Sniffing](https://attack.mitre.org/techniques/T1040)<br><br>[System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)<br><br>[System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br> | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Remote Access Software](https://attack.mitre.org/techniques/T1219)<br><br>[Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |

| TTP   | Rules |
| ----- | ----- |
| T1003 | 9     |
| T1016 | 5     |
| T1021 | 17    |
| T1027 | 4     |
| T1033 | 2     |
| T1035 | 1     |
| T1036 | 20    |
| T1040 | 10    |
| T1041 | 1     |
| T1043 | 4     |
| T1046 | 4     |
| T1047 | 4     |
| T1048 | 64    |
| T1050 | 30    |
| T1052 | 8     |
| T1053 | 19    |
| T1055 | 5     |
| T1065 | 13    |
| T1066 | 8     |
| T1068 | 20    |
| T1070 | 5     |
| T1071 | 61    |
| T1073 | 8     |
| T1075 | 13    |
| T1076 | 3     |
| T1077 | 9     |
| T1078 | 107   |
| T1083 | 3     |
| T1085 | 2     |
| T1086 | 13    |
| T1087 | 2     |
| T1088 | 5     |
| T1096 | 2     |
| T1097 | 3     |
| T1098 | 27    |
| T1100 | 4     |
| T1102 | 3     |
| T1105 | 2     |
| T1110 | 11    |
| T1117 | 2     |
| T1118 | 2     |
| T1121 | 2     |
| T1127 | 2     |
| T1133 | 8     |
| T1134 | 5     |
| T1136 | 5     |
| T1140 | 4     |
| T1168 | 1     |
| T1188 | 8     |
| T1189 | 1     |
| T1191 | 1     |
| T1196 | 1     |
| T1202 | 2     |
| T1204 | 13    |
| T1207 | 1     |
| T1208 | 13    |
| T1211 | 2     |
| T1213 | 1     |
| T1218 | 2     |
| T1219 | 29    |
| T1222 | 1     |
| T1496 | 3     |
| T1500 | 2     |
| T1550 | 2     |
| T1562 | 2     |