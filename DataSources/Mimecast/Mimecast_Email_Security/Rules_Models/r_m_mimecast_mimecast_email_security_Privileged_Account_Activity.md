Vendor: Mimecast
================
### Product: [Mimecast Email Security](../ds_mimecast_mimecast_email_security.md)
### Use-Case: [Privileged Account Activity](../../../../UseCases/uc_privileged_account_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |      5      |    5    |

| Event Type   | Rules                                                                                                                                                                                                         | Models                                                                                                             |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| app-activity | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-AT-PRIV</b>: Non-privileged user performing privileged application activity<br> ↳ <b>APP-ObT-PRIV</b>: Non-privileged user accessing privileged application object |  • <b>APP-ObT-PRIV</b>: Privileged application objects<br> • <b>APP-AT-PRIV</b>: Privileged application activities |