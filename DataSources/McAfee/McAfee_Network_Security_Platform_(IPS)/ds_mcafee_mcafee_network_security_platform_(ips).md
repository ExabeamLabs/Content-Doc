Vendor: McAfee
==============
Product: McAfee Network Security Platform (IPS)
-----------------------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     1      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                                                                                            | MITRE TTP                  | Content                                                                                                                        |
|:--------------------------------------:| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| [Other](../../../UseCases/uc_other.md) |  network-alert<br> ↳ [mcafee-ips-network-alert](Parsers/parserContent_mcafee-ips-network-alert.md)<br> ↳ [mcafee-ips-network-alert-1](Parsers/parserContent_mcafee-ips-network-alert-1.md)<br> ↳ [mcafee-network-alert](Parsers/parserContent_mcafee-network-alert.md)<br> ↳ [cef-mcafee-network-alert](Parsers/parserContent_cef-mcafee-network-alert.md)<br> ↳ [mcafee-network-alert-1](Parsers/parserContent_mcafee-network-alert-1.md)<br> | T1204 - User Execution<br> | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](Rules_Models/r_m_mcafee_mcafee_network_security_platform_(ips)_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |