Vendor: Oracle
==============
### Product: [Oracle AVDF](../ds_oracle_oracle_avdf.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |      2      |    2    |

| Event Type       | Rules                                                                                                                                                                                                                                                                                             | Models                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| failed-app-login | <b>T1133 - External Remote Services</b><br> ↳ <b>FA-OC-F</b>: First Failed activity in session from country in which organization has never had a successful activity<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity |  • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-OC</b>: Countries for organization |