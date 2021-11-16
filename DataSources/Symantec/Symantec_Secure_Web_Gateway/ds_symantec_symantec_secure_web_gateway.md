Vendor: Symantec
================
Product: Symantec Secure Web Gateway
------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  88   |   27   |     14     |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>7 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1102 - Web Service<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1566.002 - Phishing: Spearphishing Link<br>    | [<ul><li>43 Rules</li></ul><ul><li>15 Models</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Compromised_Credentials.md)        |
|    [Cryptomining](../../../UseCases/uc_cryptomining.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1496 - Resource Hijacking<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Cryptomining.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1030 - Data Transfer Size Limits<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>T1568 - Dynamic Resolution<br>    | [<ul><li>8 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1030 - Data Transfer Size Limits<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>    | [<ul><li>7 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Data_Leak.md)    |
|    [Evasion](../../../UseCases/uc_evasion.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1090.004 - T1090.004<br>    | [<ul><li>8 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Evasion.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>29 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> |    | [<ul><li>6 Rules</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Other.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1566.002 - Phishing: Spearphishing Link<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Phishing.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1102 - Web Service<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Ransomware.md)    |
|    [Workforce Protection](../../../UseCases/uc_workforce_protection.md)    |  web-activity-allowed<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br><br> web-activity-denied<br> ↳[cef-symantec-web-activity](Ps/pC_cefsymantecwebactivity.md)<br> ↳[cef-symantec-web-activity-1](Ps/pC_cefsymantecwebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_symantec_symantec_secure_web_gateway_Workforce_Protection.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                                                                                             | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                         | Credential Access | Discovery | Lateral Movement                                                                           | Collection | Command and Control                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Exfiltration                                                                                                                                                                                                                                                                          | Impact                                                                  |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ------------------------------------------------------------------------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br>[Phishing](https://attack.mitre.org/techniques/T1566)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      | [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002)<br><br> |                   |           | [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br> |            | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001)<br><br>[Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Data Transfer Size Limits](https://attack.mitre.org/techniques/T1030)<br><br>[Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)<br><br>[Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |