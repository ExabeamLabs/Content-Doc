Vendor: CatoNetworks
====================
### Product: [Cato Cloud](../ds_catonetworks_cato_cloud.md)
### Use-Case: [Risk of Attrition](../../../../UseCases/uc_risk_of_attrition.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     1      |      6      |    6    |

| Event Type           | Rules                                                                                                                                                                                                                                                                                                            | Models                                                                                                                                           |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-OU-JS-F</b>: First job search activity for user in the organization<br> ↳ <b>WEB-OU-JS-A</b>: Abnormal job search activity for user in the organization<br> ↳ <b>WEB-OG-JS-F</b>: First job search activity for user in the peer group |  • <b>WEB-OG-JS</b>: Job search activities of users in the peer group<br> • <b>WEB-OU-JS</b>: Job search activities of users in the organization |