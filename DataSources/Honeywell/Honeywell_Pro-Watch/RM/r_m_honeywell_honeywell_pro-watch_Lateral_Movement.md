Vendor: Honeywell
=================
### Product: [Honeywell Pro-Watch](../ds_honeywell_honeywell_pro-watch.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      2      |    2    |

| Event Type       | Rules                                                                                                                                                                                                              | Models                                                                            |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| account-creation | <b>T1078 - Valid Accounts</b><br> ↳ <b>A-AC-DhU-system-F</b>: First account creation by system account on asset<br><br><b>T1110 - Brute Force</b><br> ↳ <b>A-ACCT-CR-DEL</b>: Account created and deleted on asset |  • <b>A-AC-DhU-system</b>: System accounts performing account creation activities |