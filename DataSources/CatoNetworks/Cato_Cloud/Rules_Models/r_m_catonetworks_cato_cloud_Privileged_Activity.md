Vendor: CatoNetworks
====================
### Product: [Cato Cloud](../ds_catonetworks_cato_cloud.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     3      |      6      |    6    |

| Event Type           | Rules                                                                                                                                                   | Models                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| vpn-logout           | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user                                             |  • <b>WPA-UACount</b>: Count of admin privilege events for user |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller |                                                                 |
| web-activity-denied  | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller |                                                                 |