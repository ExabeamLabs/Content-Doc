ATT&CK Matrix for Enterprise
============================
### MITRE Techniques:
### MITRE Sub-techniques:
| Initial Access                                                                                                                                                                                                           | Execution                                                                                                                                                                                                                         | Persistence                                                                                                                                                                                                                                                                                                                                                         | Privilege Escalation                                                                                                                                                                                                                                                                                                                                                                     | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Credential Access                                                                                                                                                                                               | Discovery                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Lateral Movement                                                                                                                                               | Collection                                                                              | Command and Control                                                                                                                                                                                                                                                                                  | Exfiltration                                                                                                                                                                                                                                                       | Impact                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br> | [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br>[User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Create Account](https://attack.mitre.org/techniques/T1136)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Access Token Manipulation](https://attack.mitre.org/techniques/T1134)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br>[Process Injection](https://attack.mitre.org/techniques/T1055)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Indirect Command Execution](https://attack.mitre.org/techniques/T1202)<br><br>[Impair Defenses](https://attack.mitre.org/techniques/T1562)<br><br>[Rogue Domain Controller](https://attack.mitre.org/techniques/T1207)<br><br>[Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127)<br><br>[Masquerading](https://attack.mitre.org/techniques/T1036)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)<br><br>[File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222)<br><br>[Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br>[Access Token Manipulation](https://attack.mitre.org/techniques/T1134)<br><br>[Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211)<br><br>[Process Injection](https://attack.mitre.org/techniques/T1055)<br><br>[Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br>[Brute Force](https://attack.mitre.org/techniques/T1110)<br><br>[Network Sniffing](https://attack.mitre.org/techniques/T1040)<br><br> | [Network Service Scanning](https://attack.mitre.org/techniques/T1046)<br><br>[Account Discovery](https://attack.mitre.org/techniques/T1087)<br><br>[File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br>[Network Sniffing](https://attack.mitre.org/techniques/T1040)<br><br>[System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)<br><br>[System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br> | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Remote Access Software](https://attack.mitre.org/techniques/T1219)<br><br>[Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |

| TTP    | Rules |
| ------ | ----- |
| T1003  | 3012  |
| T1047  | 832   |
| T1168  | 10    |
| T1048  | 15624 |
| T1202  | 416   |
| T1562  | 416   |
| T1046  | 96    |
| T1043  | 96    |
| T1087  | 396   |
| T1088  | 1248  |
| T1121  | 208   |
| T1085  | 416   |
| T1041  | 274   |
| T1086  | 5380  |
|  T1105 | 416   |
|  T1027 | 208   |
| T1207  | 270   |
| T1208  | 10192 |
| T1204  | 31498 |
| T1127  | 208   |
| T1083  | 4980  |
| T1040  | 2912  |
| T1036  | 5952  |
| T1078  | 82886 |
| T1035  | 16    |
| T1076  | 766   |
| T1033  | 1042  |
| T1550  | 1672  |
| T1110  | 2834  |
| T1077  | 594   |
| T1075  | 8080  |
| T1196  | 208   |
| T1117  | 416   |
| T1118  | 416   |
| T1073  | 1664  |
| T1070  | 886   |
| T1191  | 208   |
| T1071  | 43852 |
|  T1191 | 208   |
| T1102  | 1822  |
| T1188  | 17820 |
|  T1121 | 208   |
| T1100  | 832   |
| T1068  | 6090  |
| T1222  | 416   |
| T1189  | 1032  |
| T1021  | 11502 |
| T1065  | 2984  |
| T1066  | 6112  |
| T1140  | 832   |
|  T1127 | 208   |
| T1500  | 416   |
| T1027  | 624   |
| T1136  | 344   |
| T1213  | 274   |
| T1133  | 9486  |
| T1496  | 1782  |
| T1211  | 416   |
| T1134  | 1040  |
| T1098  | 7034  |
| T1055  | 1248  |
| T1096  | 416   |
| T1052  | 904   |
| T1053  | 1806  |
| T1097  | 1180  |
| T1218  | 416   |
| T1219  | 9152  |
| T1016  | 1040  |
| T1050  | 1440  |