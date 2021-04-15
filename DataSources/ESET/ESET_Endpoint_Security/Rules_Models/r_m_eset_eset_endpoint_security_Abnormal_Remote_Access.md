Vendor: ESET
============
### Product: [ESET Endpoint Security](../ds_eset_eset_endpoint_security.md)
### Use-Case: [Abnormal Remote Access](../../../../UseCases/uc_abnormal_remote_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   0    |     3      |      7      |    7    |

| Event Type     | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Models |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| failed-logon   | <b>T1021.001 - Remote Services: Remote Desktop Protocol</b><b>T1110 - Brute Force</b><br> ↳ <b>FL-MULTI-USERS-L</b>: Multiple users failed to login (L)<br> ↳ <b>FL-MULTI-USERS-M</b>: Multiple users failed to login (M)<br> ↳ <b>A-FL-MULTI-DEST</b>: Failed logins to multiple destinations from host<br> ↳ <b>FL-MULTI-DEST-M</b>: Failed logins to multiple destinations from host (M)<br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user |        |
| security-alert | <b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>ALERT-DL</b>: DL Correlation rule alert on asset accessed by this user                                                                                                                                                                                                                                                                                                             |        |