Vendor: Mimecast
================
### Product: [Targeted Threat Protection - URL](../ds_mimecast_targeted_threat_protection_-_url.md)
### Use-Case: [Activity on Domain Controllers](../../../../UseCases/uc_activity_on_domain_controllers.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     2      |      2      |    2    |

| Event Type           | Rules                                                                                                                                                   | Models |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller |        |
| web-activity-denied  | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller |        |