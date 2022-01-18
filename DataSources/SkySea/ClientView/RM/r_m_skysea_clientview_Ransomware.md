Vendor: SkySea
==============
### Product: [ClientView](../ds_skysea_clientview.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     4      |     12      |   12    |

| Event Type           | Rules                                                                                                                                                                                                                                                                                                                         | Models |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity         | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                                                                                                                                                                                     |        |
| app-login            | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                                                                                                                                                                                     |        |
| file-write           | <b>T1486 - Data Encrypted for Impact</b><br> ↳ <b>FA-EXT</b>: A file has been written and is suspected of Ransomware on host                                                                                                                                                                                                  |        |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UI-Ransomware</b>: User attempted to connect to IP address which is associated to Ransomware<br><br><b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-WEB-DynamicDNS</b>: Asset attempted access to a domain generated using Dynamic DNS service |        |