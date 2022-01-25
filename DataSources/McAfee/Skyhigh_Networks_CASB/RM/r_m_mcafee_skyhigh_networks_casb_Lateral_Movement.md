Vendor: McAfee
==============
### Product: [Skyhigh Networks CASB](../ds_mcafee_skyhigh_networks_casb.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     3      |      6      |    6    |

| Event Type       | Rules                                                                                                                                                                                                                        | Models                                                                            |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| account-creation | <b>T1078 - Valid Accounts</b><br> ↳ <b>A-AC-DhU-system-F</b>: First account creation by system account on asset<br><br><b>T1110 - Brute Force</b><br> ↳ <b>A-ACCT-CR-DEL</b>: Account created and deleted on asset           |  • <b>A-AC-DhU-system</b>: System accounts performing account creation activities |
| security-alert   | <b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-DL</b>: DL Correlation rule alert on asset<br> ↳ <b>ALERT-DL</b>: DL Correlation rule alert on asset accessed by this user |                                                                                   |