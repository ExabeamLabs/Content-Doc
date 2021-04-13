Vendor: Microsoft
=================
Product: Microsoft RRA
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  12   |   5    |     3      |      2      |    2    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                                                                                                                                              | MITRE TTP                                                        | Content                                                                                                                    |
|:--------------------------------------------------------------------------:| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  authentication-successful<br> ↳ [microsoft-rra-auth-successful](Parsers/parserContent_microsoft-rra-auth-successful.md)<br><br> vpn-login<br> ↳ [microsoft-rra-vpn-login](Parsers/parserContent_microsoft-rra-vpn-login.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>   | [<ul><li>9 Rules</li></ul><ul><li>5 Models</li></ul>](Rules_Models/r_m_microsoft_microsoft_rra_Compromised_Credentials.md) |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  authentication-successful<br> ↳ [microsoft-rra-auth-successful](Parsers/parserContent_microsoft-rra-auth-successful.md)<br><br> vpn-login<br> ↳ [microsoft-rra-vpn-login](Parsers/parserContent_microsoft-rra-vpn-login.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>   | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_microsoft_microsoft_rra_Lateral_Movement.md)        |
|       [Malware Detection](../../../UseCases/uc_malware_detection.md)       |  authentication-successful<br> ↳ [microsoft-rra-auth-successful](Parsers/parserContent_microsoft-rra-auth-successful.md)<br><br> vpn-login<br> ↳ [microsoft-rra-vpn-login](Parsers/parserContent_microsoft-rra-vpn-login.md)<br> | T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br> | [<ul><li>3 Rules</li></ul>](Rules_Models/r_m_microsoft_microsoft_rra_Malware_Detection.md)                                 |
|    [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md)    |  authentication-successful<br> ↳ [microsoft-rra-auth-successful](Parsers/parserContent_microsoft-rra-auth-successful.md)<br><br> vpn-login<br> ↳ [microsoft-rra-vpn-login](Parsers/parserContent_microsoft-rra-vpn-login.md)<br> | T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br> | [<ul><li>3 Rules</li></ul>](Rules_Models/r_m_microsoft_microsoft_rra_Ransomware_Detection.md)                              |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |