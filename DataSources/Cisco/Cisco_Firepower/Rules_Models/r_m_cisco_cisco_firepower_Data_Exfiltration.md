Vendor: Cisco
=============
### Product: [Cisco Firepower](../ds_cisco_cisco_firepower.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     4      |      9      |    9    |

| Event Type           | Rules                                                                                                                                                                                                                                                                                                   | Models |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| netflow-connection   | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>A-NETFLOW-BitTorrent</b>: Asset accessed BitTorrent application                                                                                                                                                                          |        |
| web-activity-allowed | <b>T1041 - Exfiltration Over C2 Channel</b><br> ↳ <b>WEB-New-File-20</b>: User with no web activity history has uploaded 20MB or more<br><br><b>T1048 - Exfiltration Over Alternative Protocol</b><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-EXFIL-ASSET</b>: Large amount of data exfiltrated from host |        |
| web-activity-denied  | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>New-File-20-Block</b>: User with no web activity history was blocked from uploading 20MB or more                                                                                                                                         |        |