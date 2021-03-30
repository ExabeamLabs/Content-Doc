Vendor: IBM
===========
Product: Proventia Network IPS
------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   6    |     2      |      1      |    1    |

|                Use-Case                | Event Types/Parsers                                                                          | MITRE TTP                                   | Content                                                                                                    |
|:--------------------------------------:| -------------------------------------------------------------------------------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) |  network-alert<br> ↳ [q-ibm-network-alert](Parsers/parserContent_q-ibm-network-alert.md)<br> | T1066 - T1066<br>T1204 - User Execution<br> | [<ul><li>9 Rules</li></ul><ul><li>6 Models</li></ul>](Rules_Models/r_m_ibm_proventia_network_ips_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |