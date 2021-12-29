Vendor: Cisco
=============
### Product: [IronPort Email](../ds_cisco_ironport_email.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |      6      |    6    |

| Event Type          | Rules                                                                                                                                                                                                                          | Models                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| web-activity-denied | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UT-TOW-A</b>: Abnormal day for this user to access the web via the organization<br> ↳ <b>WEB-UZ-F</b>: First web activity for this user in this zone |  • <b>WEB-UZ</b>: Network zones where a user performs web activity from<br> • <b>WEB-UT-TOW</b>: Web activity activity time for user |