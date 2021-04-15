Vendor: Citrix
==============
### Product: [Citrix Netscaler VPN](../ds_citrix_citrix_netscaler_vpn.md)
### Use-Case: [Abnormal Application Access](../../../../UseCases/uc_abnormal_application_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     2      |      6      |    6    |

| Event Type | Rules                                                                                                                                                                                                                                   | Models                                                                                                                                           |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| vpn-logout | <b>T1110 - Brute Force</b><br> ↳ <b>APP-UFL-COUNT</b>: Abnormal number of failed application logins for user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>APP-UOb-Number</b>: Abnormal number of application objects accessed for user |  • <b>APP-UFL-COUNT</b>: Count of failed application logins in a session<br> • <b>APP-UOb-Number</b>: Count of app objects accessed in a session |