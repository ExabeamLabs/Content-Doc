Vendor: CatoNetworks
====================
### Product: [Cato Cloud](../ds_catonetworks_cato_cloud.md)
### Use-Case: [Data Exfiltration via Web](../../../../UseCases/uc_data_exfiltration_via_web.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     3      |      6      |    6    |

| Event Type           | Rules                                                                                                                                                                                                         | Models |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| web-activity-allowed | <b>T1030 - Data Transfer Size Limits</b><br> ↳ <b>A-WEB-EXFIL-ASSET</b>: Large amount of data exfiltrated from host<br> ↳ <b>WEB-New-File-20</b>: User with no web activity history has uploaded 20MB or more |        |
| web-activity-denied  | <b>T1030 - Data Transfer Size Limits</b><br> ↳ <b>New-File-20-Block</b>: User with no web activity history was blocked from uploading 20MB or more                                                            |        |