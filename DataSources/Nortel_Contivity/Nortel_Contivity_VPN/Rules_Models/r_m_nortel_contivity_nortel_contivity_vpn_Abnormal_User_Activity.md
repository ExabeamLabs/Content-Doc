Vendor: Nortel Contivity
========================
### Product: [Nortel Contivity VPN](../ds_nortel_contivity_nortel_contivity_vpn.md)
### Use-Case: [Abnormal User Activity](../../../../UseCases/uc_abnormal_user_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |      1      |    1    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                        | Models                                                                     |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| vpn-logout | <b>T1078 - Valid Accounts</b><br> ↳ <b>DC14g-new</b>: Abnormal number of accessed assets for group of new user<br> ↳ <b>APP-UAgC-F</b>: First activity from country and first os/browser/user agent for user in same session<br><br><b>T1110 - Brute Force</b><br> ↳ <b>AUTH-F-COUNT</b>: Abnormal number of failed authentications for user |  • <b>AUTH-F-COUNT</b>: Count of failed authentication events in a session |