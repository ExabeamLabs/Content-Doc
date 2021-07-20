Vendor: Cisco
=============
Product: Adaptive Security Appliance
------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  27   |   15   |     5      |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  network-connection-successful<br> ↳[cisco-asa-connection-built-302013](Ps/pC_ciscoasaconnectionbuilt302013.md)<br> | T1046 - Network Service Scanning<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_cisco_adaptive_security_appliance_Compromised_Credentials.md) |
|    [Cryptomining](../../../UseCases/uc_cryptomining.md)    |  network-connection-successful<br> ↳[cisco-asa-connection-built-302013](Ps/pC_ciscoasaconnectionbuilt302013.md)<br> | T1496 - Resource Hijacking<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_cisco_adaptive_security_appliance_Cryptomining.md)    |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  network-connection-successful<br> ↳[cisco-asa-connection-built-302013](Ps/pC_ciscoasaconnectionbuilt302013.md)<br> | T1046 - Network Service Scanning<br>T1071 - Application Layer Protocol<br>T1090.002 - Proxy: External Proxy<br>T1571 - Non-Standard Port<br> | [<ul><li>24 Rules</li></ul><ul><li>15 Models</li></ul>](RM/r_m_cisco_adaptive_security_appliance_Lateral_Movement.md)      |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  network-connection-successful<br> ↳[cisco-asa-connection-built-302013](Ps/pC_ciscoasaconnectionbuilt302013.md)<br> | T1071 - Application Layer Protocol<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_cisco_adaptive_security_appliance_Ransomware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery                                                                     | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                                                                                           | Exfiltration | Impact                                                                  |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | ----------------------------------------------------------------------------- | ---------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------- |
|                |           |             |                      |                 |                   | [Network Service Scanning](https://attack.mitre.org/techniques/T1046)<br><br> |                  |            | [Non-Standard Port](https://attack.mitre.org/techniques/T1571)<br><br>[Proxy: External Proxy](https://attack.mitre.org/techniques/T1090/002)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |