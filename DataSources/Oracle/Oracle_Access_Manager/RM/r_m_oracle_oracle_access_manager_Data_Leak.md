Vendor: Oracle
==============
### Product: [Oracle Access Manager](../ds_oracle_oracle_access_manager.md)
### Use-Case: [Data Leak](../../../../UseCases/uc_data_leak.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     2      |      5      |    5    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Models |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-InRule-Fin</b>: User has created an inbox forwarding rule to forward emails containing financial keywords<br><br><b>T1114.003 - Email Collection: Email Forwarding Rule</b><br> ↳ <b>EM-InRule-EX</b>: User has created an inbox forwarding rule to forward email to an external domain email<br> ↳ <b>EM-InRule-Public</b>: User has created an inbox forwarding rule to forward email to a public email domain |        |