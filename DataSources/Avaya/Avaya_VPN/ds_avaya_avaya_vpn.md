Vendor: Avaya
=============
Product: Avaya VPN
------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  26   |   8    |     3      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  dns-query<br> ↳[s-avaya-vpn-login](Ps/pC_savayavpnlogin.md)<br><br> vpn-login<br> ↳[s-avaya-failed-vpn-login](Ps/pC_savayafailedvpnlogin.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br> | [<ul><li>15 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_avaya_avaya_vpn_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  dns-query<br> ↳[s-avaya-vpn-login](Ps/pC_savayavpnlogin.md)<br><br> vpn-login<br> ↳[s-avaya-failed-vpn-login](Ps/pC_savayafailedvpnlogin.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br> | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_avaya_avaya_vpn_Compromised_Credentials.md)    |
|    [Evasion](../../../UseCases/uc_evasion.md)    |  dns-query<br> ↳[s-avaya-vpn-login](Ps/pC_savayavpnlogin.md)<br><br> vpn-login<br> ↳[s-avaya-failed-vpn-login](Ps/pC_savayafailedvpnlogin.md)<br> | T1090.003 - Proxy: Multi-hop Proxy<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_avaya_avaya_vpn_Evasion.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  dns-query<br> ↳[s-avaya-vpn-login](Ps/pC_savayavpnlogin.md)<br><br> vpn-login<br> ↳[s-avaya-failed-vpn-login](Ps/pC_savayafailedvpnlogin.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_avaya_avaya_vpn_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  dns-query<br> ↳[s-avaya-vpn-login](Ps/pC_savayavpnlogin.md)<br><br> vpn-login<br> ↳[s-avaya-failed-vpn-login](Ps/pC_savayafailedvpnlogin.md)<br> |    | [<ul><li>2 Rules</li></ul>](RM/r_m_avaya_avaya_vpn_Other.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  dns-query<br> ↳[s-avaya-vpn-login](Ps/pC_savayavpnlogin.md)<br><br> vpn-login<br> ↳[s-avaya-failed-vpn-login](Ps/pC_savayafailedvpnlogin.md)<br> | T1133 - External Remote Services<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_avaya_avaya_vpn_Privilege_Abuse.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  dns-query<br> ↳[s-avaya-vpn-login](Ps/pC_savayavpnlogin.md)<br><br> vpn-login<br> ↳[s-avaya-failed-vpn-login](Ps/pC_savayafailedvpnlogin.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_avaya_avaya_vpn_Ransomware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |