Vendor: Fortinet
================
### Product: [Fortinet VPN](../ds_fortinet_fortinet_vpn.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   1    |     4      |      3      |    3    |

| Event Type          | Rules                                                                                                                                                                                                                                                                                                         | Models                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| vpn-login           | <b>T1133 - External Remote Services</b><br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>VPN31</b>: VPN connection using a disabled account                                                                                                                                                          |                                                                 |
| vpn-logout          | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user                                                                                                                                                                                                   |  • <b>WPA-UACount</b>: Count of admin privilege events for user |
| web-activity-denied | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller<br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller |                                                                 |