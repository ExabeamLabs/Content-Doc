Vendor: Squid
=============
Product: Squid
--------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  58   |   20   |     10     |      2      |    2    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MITRE TTP                                                                                                                                                                                                                                                                                                                                                    | Content                                                                                                         |
|:--------------------------------------------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  web-activity-allowed<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br><br> web-activity-denied<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>                                                                                                                                                                                                                                                                                                    | [<ul><li>11 Rules</li></ul><ul><li>8 Models</li></ul>](Rules_Models/r_m_squid_squid_Compromised_Credentials.md) |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  web-activity-allowed<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br><br> web-activity-denied<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br> | T1030 - Data Transfer Size Limits<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>                                                                                                                                                                                   | [<ul><li>3 Rules</li></ul>](Rules_Models/r_m_squid_squid_Data_Exfiltration.md)                                  |
|          [Internal Fraud](../../../UseCases/uc_internal_fraud.md)          |  web-activity-allowed<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br><br> web-activity-denied<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>                                                                                                                                                                                                                                                                                                    | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](Rules_Models/r_m_squid_squid_Internal_Fraud.md)           |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  web-activity-allowed<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br><br> web-activity-denied<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>                                                                                                                                                                                                                                                              | [<ul><li>5 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_squid_squid_Lateral_Movement.md)         |
|       [Malware Detection](../../../UseCases/uc_malware_detection.md)       |  web-activity-allowed<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br><br> web-activity-denied<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1102 - Web Service<br>T1496 - Resource Hijacking<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>39 Rules</li></ul><ul><li>8 Models</li></ul>](Rules_Models/r_m_squid_squid_Malware_Detection.md)       |
|                [Phishing](../../../UseCases/uc_phishing.md)                |  web-activity-allowed<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br><br> web-activity-denied<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1566.002 - Phishing: Spearphishing Link<br>T1568 - Dynamic Resolution<br>                                                                                                                                                                                    | [<ul><li>8 Rules</li></ul>](Rules_Models/r_m_squid_squid_Phishing.md)                                           |
|    [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md)    |  web-activity-allowed<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br><br> web-activity-denied<br> ↳ [squid-web-activity-1](Parsers/parserContent_squid-web-activity-1.md)<br> ↳ [squid-web-activity](Parsers/parserContent_squid-web-activity.md)<br> ↳ [squid-web-activity-4](Parsers/parserContent_squid-web-activity-4.md)<br> ↳ [squid-web-activity-3](Parsers/parserContent_squid-web-activity-3.md)<br> ↳ [squid-web-activity-2](Parsers/parserContent_squid-web-activity-2.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1102 - Web Service<br>T1496 - Resource Hijacking<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>36 Rules</li></ul><ul><li>7 Models</li></ul>](Rules_Models/r_m_squid_squid_Ransomware_Detection.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                     | Execution | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                         | Credential Access | Discovery | Lateral Movement                                                                           | Collection | Command and Control                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Exfiltration                                                                                                                                                                                                                                                                          | Impact                                                                  |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ----------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ------------------------------------------------------------------------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)<br><br>[Phishing](https://attack.mitre.org/techniques/T1566)<br><br> |           |             |                      | [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002)<br><br> |                   |           | [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br> |            | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001)<br><br>[Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Data Transfer Size Limits](https://attack.mitre.org/techniques/T1030)<br><br>[Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)<br><br>[Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |