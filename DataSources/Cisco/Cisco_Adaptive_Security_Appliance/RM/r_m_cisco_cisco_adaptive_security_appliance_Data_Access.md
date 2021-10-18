Vendor: Cisco
=============
### Product: [Cisco Adaptive Security Appliance](../ds_cisco_cisco_adaptive_security_appliance.md)
### Use-Case: [Data Access](../../../../UseCases/uc_data_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     3      |     13      |   13    |

| Event Type      | Rules                                                                                                                                                                                                                                   | Models                                                                                                                                           |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| process-created | <b>T1003 - OS Credential Dumping</b><br> ↳ <b>CP-Sensitive-Files</b>: Copying sensitive files with credential data                                                                                                                      |                                                                                                                                                  |
| vpn-logout      | <b>T1110 - Brute Force</b><br> ↳ <b>APP-UFL-COUNT</b>: Abnormal number of failed application logins for user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>APP-UOb-Number</b>: Abnormal number of application objects accessed for user |  • <b>APP-UFL-COUNT</b>: Count of failed application logins in a session<br> • <b>APP-UOb-Number</b>: Count of app objects accessed in a session |