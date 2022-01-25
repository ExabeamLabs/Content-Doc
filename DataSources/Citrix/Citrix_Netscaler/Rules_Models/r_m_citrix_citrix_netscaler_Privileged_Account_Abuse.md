Vendor: Citrix
==============
### Product: [Citrix Netscaler](../ds_citrix_citrix_netscaler.md)
### Use-Case: [Privileged Account Abuse](../../../../UseCases/uc_privileged_account_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |      6      |    6    |

| Event Type   | Rules                                                                                                                                                                                                         | Models                                                                                                             |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| app-activity | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-AT-PRIV</b>: Non-privileged user performing privileged application activity<br> ↳ <b>APP-ObT-PRIV</b>: Non-privileged user accessing privileged application object |  • <b>APP-ObT-PRIV</b>: Privileged application objects<br> • <b>APP-AT-PRIV</b>: Privileged application activities |