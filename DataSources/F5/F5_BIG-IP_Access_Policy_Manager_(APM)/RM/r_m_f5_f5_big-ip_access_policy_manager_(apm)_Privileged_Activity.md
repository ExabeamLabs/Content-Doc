Vendor: F5
==========
### Product: [F5 BIG-IP Access Policy Manager (APM)](../ds_f5_f5_big-ip_access_policy_manager_(apm).md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   1    |     2      |      6      |    6    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                              | Models                                                   |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| app-activity | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-AT-PRIV</b>: Non-privileged user performing privileged application activity                                                                                                                                                             |  • <b>APP-AT-PRIV</b>: Privileged application activities |
| vpn-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>DC20a</b>: High-privilege user used during session<br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>VPN31</b>: VPN connection using a disabled account<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>VPN31</b>: VPN connection using a disabled account |                                                          |