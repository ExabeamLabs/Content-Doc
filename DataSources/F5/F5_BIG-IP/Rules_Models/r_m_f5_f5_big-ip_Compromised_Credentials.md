Vendor: F5
==========
### Product: [F5 BIG-IP](../ds_f5_f5_big-ip.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   2    |     2      |      5      |    5    |

| Event Type       | Rules                                                                                                                                                                                                                                                                      | Models                                              |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| failed-logon     | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account                                                                                                              |  • <b>AE-UA</b>: All activity for users             |
| failed-vpn-login | <b>T1133 - External Remote Services</b><br> ↳ <b>SEQ-UH-15</b>: Failed VPN login                                                                                                                                                                                           |                                                     |
| remote-logon     | <b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries                                                                         |                                                     |
| vpn-login        | <b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>VPN-GsH-F</b>: First VPN connection from device for peer group<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries |  • <b>VPN-GsH</b>: VPN endpoints in this peer group |