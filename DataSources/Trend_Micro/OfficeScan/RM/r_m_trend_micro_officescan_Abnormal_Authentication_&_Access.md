Vendor: Trend Micro
===================
### Product: [OfficeScan](../ds_trend_micro_officescan.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   3    |     2      |      7      |    7    |

| Event Type              | Rules                                                                                                                                                                                                                          | Models                                                                                                                               |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| account-password-change | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user                                                                                                       |  • <b>AE-UA</b>: All activity for users                                                                                              |
| web-activity-denied     | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UT-TOW-A</b>: Abnormal day for this user to access the web via the organization<br> ↳ <b>WEB-UZ-F</b>: First web activity for this user in this zone |  • <b>WEB-UZ</b>: Network zones where a user performs web activity from<br> • <b>WEB-UT-TOW</b>: Web activity activity time for user |