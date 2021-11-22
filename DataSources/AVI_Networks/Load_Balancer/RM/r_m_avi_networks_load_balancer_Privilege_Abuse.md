Vendor: AVI Networks
====================
### Product: [Load Balancer](../ds_avi_networks_load_balancer.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   2    |     2      |      1      |    1    |

| Event Type     | Rules                                                                                                                                                                                                                                                                                                                                                          | Models                                                                             |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| account-switch | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>DC18-New</b>: New account switch to privileged account<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>AS-UA-A</b>: Abnormal switch to target account for user<br> ↳ <b>AS-UA-F-PRIV</b>: Account switch to a privileged or executive account<br> ↳ <b>AS-UA-FS</b>: First account switch for user |  • <b>DC18</b>: Secondary accounts<br> • <b>AS-UA</b>: Target credentials for user |