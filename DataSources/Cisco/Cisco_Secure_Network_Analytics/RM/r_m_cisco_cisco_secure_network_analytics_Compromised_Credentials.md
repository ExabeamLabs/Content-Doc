Vendor: Cisco
=============
### Product: [Cisco Secure Network Analytics](../ds_cisco_cisco_secure_network_analytics.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     2      |      1      |    1    |

| Event Type | Rules                                                                                                                                                                                                                                  | Models                                                                                                                           |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| vpn-logout | <b>T1110 - Brute Force</b><br> ↳ <b>APP-UFL-COUNT</b>: Abnormal number of failed application logins for user<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>VPN-BSum</b>: Abnormal amount of data uploaded during VPN Session |  • <b>APP-UFL-COUNT</b>: Count of failed application logins in a session<br> • <b>VPN-BSum</b>: Sum of bytes uploaded during VPN |