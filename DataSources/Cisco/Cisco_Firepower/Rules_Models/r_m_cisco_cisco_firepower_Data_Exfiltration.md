Vendor: Cisco
=============
### Product: [Cisco Firepower](../ds_cisco_cisco_firepower.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     5      |     11      |   11    |

| Event Type           | Rules                                                                                                                                                                                                                                                              | Models |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| netflow-connection   | <b>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol</b><b>T1071.002 - Application Layer Protocol: File Transfer Protocols</b><br> ↳ <b>A-NETFLOW-BitTorrent</b>: Asset accessed BitTorrent application |        |
| web-activity-allowed | <b>T1030 - Data Transfer Size Limits</b><br> ↳ <b>A-WEB-EXFIL-ASSET</b>: Large amount of data exfiltrated from host<br> ↳ <b>WEB-New-File-20</b>: User with no web activity history has uploaded 20MB or more                                                      |        |
| web-activity-denied  | <b>T1030 - Data Transfer Size Limits</b><br> ↳ <b>New-File-20-Block</b>: User with no web activity history was blocked from uploading 20MB or more                                                                                                                 |        |