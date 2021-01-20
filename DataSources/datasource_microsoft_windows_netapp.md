Vendor: Microsoft Windows
=========================
Product: NetApp
---------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |      4      |    4    |

|                              Use-Case                               | Activity Types                      | Event Types/Parsers                                                                                                                                                                   | MITRE TTP                  | Content                   |
|:-------------------------------------------------------------------:| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------- |
|    [Malware Detection](../UseCases/usecase_malware_detection.md)    | <ul><li>Endpoint Activity</li></ul> |  file-alert<br> ↳ [s-xml-4656-netapp](../Parsers/parserContent_s-xml-4656-netapp.md)<br><br> file-delete<br> ↳ [s-xml-4660-netapp](../Parsers/parserContent_s-xml-4660-netapp.md)<br> | T1204 - User Execution<br> | <ul><li>2 Rules</li></ul> |
| [Ransomware Detection](../UseCases/usecase_ransomware_detection.md) | <ul><li>Endpoint Activity</li></ul> |  file-alert<br> ↳ [s-xml-4656-netapp](../Parsers/parserContent_s-xml-4656-netapp.md)<br><br> file-delete<br> ↳ [s-xml-4660-netapp](../Parsers/parserContent_s-xml-4660-netapp.md)<br> | T1204 - User Execution<br> | <ul><li>2 Rules</li></ul> |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            |                     |              |        |