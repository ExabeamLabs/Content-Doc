Vendor: RSA
===========
### Product: [RSA](../ds_rsa_rsa.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     2      |      1      |    1    |

| Event Type         | Rules                                                                                                                                                                                                                                                                                                                                               | Models |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| netflow-connection | <b>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol</b><br> ↳ <b>A-NETFLOW-BitTorrent</b>: Asset accessed BitTorrent application<br><br><b>T1071.002 - Application Layer Protocol: File Transfer Protocols</b><br> ↳ <b>A-NETFLOW-BitTorrent</b>: Asset accessed BitTorrent application |        |