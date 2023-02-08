Vendor: Lumension
=================
Product: Lumension
------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  18   |   6    |         3          |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Leak](../../../UseCases/uc_data_leak.md) |  usb-insert<br> ↳[s-lumension-usb](Ps/pC_slumensionusb.md)<br> ↳[lumension-usb-insert-2](Ps/pC_lumensionusbinsert2.md)<br> ↳[lumension-usb-insert-1](Ps/pC_lumensionusbinsert1.md)<br><br> usb-read<br> ↳[lumension-usb-read](Ps/pC_lumensionusbread.md)<br><br> usb-write<br> ↳[lumension-usb-write](Ps/pC_lumensionusbwrite.md)<br> | T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br>T1091 - Replication Through Removable Media<br> | [<ul><li>14 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_lumension_lumension_Data_Leak.md) |
|   [Malware](../../../UseCases/uc_malware.md)   |  usb-read<br> ↳[lumension-usb-read](Ps/pC_lumensionusbread.md)<br><br> usb-write<br> ↳[lumension-usb-write](Ps/pC_lumensionusbwrite.md)<br>    | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_lumension_lumension_Malware.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                           | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement                                                                         | Collection | Command and Control | Exfiltration                                                                                                                                                                                            | Impact |
| ---------------------------------------------------------------------------------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------------------------------------------------------------------------------- | ---------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091)<br><br> |           |             |                      |                 |                   |           | [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091)<br><br> |            |                     | [Exfiltration Over Physical Medium: Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |