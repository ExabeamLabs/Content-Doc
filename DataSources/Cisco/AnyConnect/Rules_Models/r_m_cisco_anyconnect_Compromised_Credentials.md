Vendor: Cisco
=============
### Product: [AnyConnect](../ds_cisco_anyconnect.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   4    |     4      |      3      |    3    |

| Event Type      | Rules                                                                                                                                                                                                                                                                      | Models                                                                                                                                           |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| process-network | <b>T1003 - OS Credential Dumping</b><br> ↳ <b>EPA-UH-Pen-F</b>: Known pentest tool used                                                                                                                                                                                    |  • <b>EPA-UH-Pen</b>: Malicious tools used by user                                                                                               |
| vpn-login       | <b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>VPN-GsH-F</b>: First VPN connection from device for peer group<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries |  • <b>VPN-GsH</b>: VPN endpoints in this peer group                                                                                              |
| vpn-logout      | <b>T1110 - Brute Force</b><br> ↳ <b>APP-UFL-COUNT</b>: Abnormal number of failed application logins for user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>APP-UOb-Number</b>: Abnormal number of application objects accessed for user                                    |  • <b>APP-UFL-COUNT</b>: Count of failed application logins in a session<br> • <b>APP-UOb-Number</b>: Count of app objects accessed in a session |