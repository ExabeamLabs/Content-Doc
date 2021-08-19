Vendor: Citrix
==============
Product: Netscaler WAF
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  32   |   16   |     4      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|     [Cryptomining](../../../UseCases/uc_cryptomining.md)     |  network-connection-failed<br> ↳[netscaler-network-connection-2](Ps/pC_netscalernetworkconnection2.md)<br> ↳[netscaler-network-connection-3](Ps/pC_netscalernetworkconnection3.md)<br> ↳[netscaler-network-connection](Ps/pC_netscalernetworkconnection.md)<br><br> network-connection-successful<br> ↳[netscaler-network-connection-2](Ps/pC_netscalernetworkconnection2.md)<br> ↳[netscaler-network-connection-3](Ps/pC_netscalernetworkconnection3.md)<br> ↳[netscaler-network-connection](Ps/pC_netscalernetworkconnection.md)<br> | T1496 - Resource Hijacking<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_citrix_netscaler_waf_Cryptomining.md)    |
| [Lateral Movement](../../../UseCases/uc_lateral_movement.md) |  network-connection-failed<br> ↳[netscaler-network-connection-2](Ps/pC_netscalernetworkconnection2.md)<br> ↳[netscaler-network-connection-3](Ps/pC_netscalernetworkconnection3.md)<br> ↳[netscaler-network-connection](Ps/pC_netscalernetworkconnection.md)<br><br> network-connection-successful<br> ↳[netscaler-network-connection-2](Ps/pC_netscalernetworkconnection2.md)<br> ↳[netscaler-network-connection-3](Ps/pC_netscalernetworkconnection3.md)<br> ↳[netscaler-network-connection](Ps/pC_netscalernetworkconnection.md)<br> | T1071 - Application Layer Protocol<br>T1090.002 - Proxy: External Proxy<br>T1571 - Non-Standard Port<br> | [<ul><li>29 Rules</li></ul><ul><li>16 Models</li></ul>](RM/r_m_citrix_netscaler_waf_Lateral_Movement.md) |
[Next Page -->>](2_ds_citrix_netscaler_waf.md)

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                                                                                           | Exfiltration | Impact                                                                  |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------- |
|                |           |             |                      |                 |                   |           |                  |            | [Non-Standard Port](https://attack.mitre.org/techniques/T1571)<br><br>[Proxy: External Proxy](https://attack.mitre.org/techniques/T1090/002)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |