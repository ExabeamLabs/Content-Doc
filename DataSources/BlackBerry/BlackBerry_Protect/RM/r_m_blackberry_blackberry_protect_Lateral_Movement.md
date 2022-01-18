Vendor: BlackBerry
==================
### Product: [BlackBerry Protect](../ds_blackberry_blackberry_protect.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     2      |      4      |    4    |

| Event Type     | Rules                                                                                                                                                                                                                                           | Models                                                                                                                                                                                           |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| security-alert | <b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>ALERT-DL</b>: DL Correlation rule alert on asset accessed by this user                                                                                |                                                                                                                                                                                                  |
| vpn-logout     | <b>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting</b><br> ↳ <b>KL-USnCOUNT-A</b>: Abnormal number of services used to obtain TGTs by user<br> ↳ <b>KL-GSnCOUNT-A</b>: Abnormal number of services used to obtain TGTs by peer group |  • <b>KL-GSnCOUNT</b>: Count of services used to obtain kerberos TGTs in a session for peer group<br> • <b>KL-USnCOUNT</b>: Count of services used to obtain kerberos TGTs in a session for user |