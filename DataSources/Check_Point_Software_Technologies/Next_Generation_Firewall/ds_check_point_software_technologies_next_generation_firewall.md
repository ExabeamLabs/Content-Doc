Vendor: Check Point Software Technologies
=========================================
Product: Next Generation Firewall
---------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   4    |     2      |      1      |    1    |

|                Use-Case                | Activity Types                                                                                            | Event Types/Parsers                                                                              | MITRE TTP                                   | Content                                                                                                                                     |
|:--------------------------------------:| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| [Other](../../../UseCases/uc_other.md) | <ul><li>Endpoint Activity</li><li>Network Alert</li><li>Process Activity</li><li>Security Alert</li></ul> |  network-alert<br> ↳ [leef-checkpoint-alert](Parsers/parserContent_leef-checkpoint-alert.md)<br> | T1066 - T1066<br>T1204 - User Execution<br> | [<ul><li>9 Rules</li></ul><ul><li>4 Models</li></ul>](Rules_Models/r_m_check_point_software_technologies_next_generation_firewall_Other.md) |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |