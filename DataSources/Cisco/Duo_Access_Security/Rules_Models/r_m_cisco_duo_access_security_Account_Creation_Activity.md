Vendor: Cisco
=============
### Product: [Duo Access Security](../ds_cisco_duo_access_security.md)
### Use-Case: [Account Creation Activity](../../../../UseCases/uc_account_creation_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   3    |     1      |      6      |    6    |

| Event Type       | Rules                                                                                                                                                                                                                                                                                                                                                                                  | Models                                                                                                                                                                                      |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| account-creation | <b>T1136.001 - Create Account: Create: Local Account</b><br> ↳ <b>AC-DhU-system-F</b>: First account creation by system account on asset<br> ↳ <b>AC-DhU-system-A</b>: Abnormal account creation by system account on asset<br> ↳ <b>AC-UH-F</b>: First account creation activity from asset for user<br> ↳ <b>AC-LocUA-F-new</b>: First account creation activity by a new local user |  • <b>AE-UA</b>: All activity for users<br> • <b>AC-UH</b>: Account creation activity on host for user<br> • <b>A-AC-DhU-system</b>: System accounts performing account creation activities |