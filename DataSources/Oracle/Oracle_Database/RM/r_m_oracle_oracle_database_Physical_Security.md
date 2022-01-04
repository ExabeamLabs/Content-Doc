Vendor: Oracle
==============
### Product: [Oracle Database](../ds_oracle_oracle_database.md)
### Use-Case: [Physical Security](../../../../UseCases/uc_physical_security.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   3    |     1      |      7      |    7    |

| Event Type             | Rules                                                                                                                                                                                                                                                                                                                                                                                           | Models                                                                                                                                          |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| failed-physical-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>FPA-UC-F</b>: Failed physical access in new location for user<br> ↳ <b>FPA-UB-F</b>: Failed physical access in new building for user<br> ↳ <b>FPA-UD-F</b>: Failed physical access to a door user has never successfully accessed<br> ↳ <b>FPA-UTi-A</b>: Failed badge access at abnormal time<br> ↳ <b>FPA-DU</b>: Failed badge access by disabled user |  • <b>PA-UTi</b>: Badge access time<br> • <b>PA-UD</b>: Door level badge access by user<br> • <b>PA-UB</b>: Building level badge access by user |