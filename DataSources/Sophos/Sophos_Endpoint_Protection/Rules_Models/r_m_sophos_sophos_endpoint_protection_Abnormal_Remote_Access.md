Vendor: Sophos
==============
### Product: [Sophos Endpoint Protection](../ds_sophos_sophos_endpoint_protection.md)
### Use-Case: [Abnormal Remote Access](../../../../UseCases/uc_abnormal_remote_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |     10      |   10    |

| Event Type     | Rules                                                                                                                                                            | Models |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| security-alert | <b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>ALERT-DL</b>: DL Correlation rule alert on asset accessed by this user |        |
| vpn-logout     | <b>T1078 - Valid Accounts</b><br> ↳ <b>DC14g-new</b>: Abnormal number of accessed assets for group of new user                                                   |        |