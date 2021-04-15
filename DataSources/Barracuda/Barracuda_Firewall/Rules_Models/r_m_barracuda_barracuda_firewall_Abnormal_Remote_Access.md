Vendor: Barracuda
=================
### Product: [Barracuda Firewall](../ds_barracuda_barracuda_firewall.md)
### Use-Case: [Abnormal Remote Access](../../../../UseCases/uc_abnormal_remote_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   0    |     3      |      5      |    5    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Models |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| failed-logon | <b>T1021.001 - Remote Services: Remote Desktop Protocol</b><b>T1110 - Brute Force</b><br> ↳ <b>FL-MULTI-USERS-L</b>: Multiple users failed to login (L)<br> ↳ <b>FL-MULTI-USERS-M</b>: Multiple users failed to login (M)<br> ↳ <b>A-FL-MULTI-DEST</b>: Failed logins to multiple destinations from host<br> ↳ <b>FL-MULTI-DEST-M</b>: Failed logins to multiple destinations from host (M)<br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user |        |
| vpn-logout   | <b>T1078 - Valid Accounts</b><br> ↳ <b>DC14g-new</b>: Abnormal number of accessed assets for group of new user                                                                                                                                                                                                                                                                                                                                                               |        |