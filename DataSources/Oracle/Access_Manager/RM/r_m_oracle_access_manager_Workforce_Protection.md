Vendor: Oracle
==============
### Product: [Access Manager](../ds_oracle_access_manager.md)
### Use-Case: [Workforce Protection](../../../../UseCases/uc_workforce_protection.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      5      |    5    |

| Event Type             | Rules                                                                                      | Models                              |
| ---------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------- |
| failed-physical-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>FPA-UTi-A</b>: Failed badge access at abnormal time |  • <b>PA-UTi</b>: Badge access time |
| physical-access        | <b>T1078 - Valid Accounts</b><br> ↳ <b>PA-UTi-A</b>: Badge access at abnormal time         |  • <b>PA-UTi</b>: Badge access time |