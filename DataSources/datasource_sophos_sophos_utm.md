Vendor: Sophos
==============
Product: Sophos UTM
-------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  34   |   8    |     4      |      1      |    1    |

|               Use-Case                | Activity Types                                 | Event Types/Parsers                                                                                                                                                                                                                                                                                   | MITRE TTP                                                                                                     | Content                                              |
|:-------------------------------------:| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| [Other](../UseCases/usecase_other.md) | <ul><li>Network</li><li>Web Activity</li></ul> |  <br> ↳ [sophos-proxy](../Parsers/parserContent_sophos-proxy.md)<br> ↳ [sophos-proxy-2](../Parsers/parserContent_sophos-proxy-2.md)<br><br> web-activity-denied<br> ↳ [sophos-proxy](../Parsers/parserContent_sophos-proxy.md)<br> ↳ [sophos-proxy-1](../Parsers/parserContent_sophos-proxy-1.md)<br> | T1071 - Application Layer Protocol<br>T1102 - Web Service<br>T1188 - T1188<br>T1189 - Drive-by Compromise<br> | <ul><li>34 Rules</li></ul><ul><li>8 Models</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                           | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                             | Exfiltration | Impact |
| ------------------------------------------------------------------------ | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br> |           |             |                      |                 |                   |           |                  |            | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> |              |        |