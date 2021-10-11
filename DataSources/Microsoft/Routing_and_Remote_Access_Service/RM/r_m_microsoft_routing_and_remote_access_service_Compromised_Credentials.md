Vendor: Microsoft
=================
### Product: [Routing and Remote Access Service](../ds_microsoft_routing_and_remote_access_service.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |      2      |    2    |

| Event Type                | Rules                                                                                                                                                                                                                                                                                                                                                                                                            | Models                                              |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| authentication-successful | <b>T1078 - Valid Accounts</b><br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries                                                                         |                                                     |
| vpn-login                 | <b>T1078 - Valid Accounts</b><br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>VPN-GsH-F</b>: First VPN connection from device for peer group<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries |  • <b>VPN-GsH</b>: VPN endpoints in this peer group |