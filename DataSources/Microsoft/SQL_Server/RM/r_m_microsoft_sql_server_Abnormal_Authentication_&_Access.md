Vendor: Microsoft
=================
### Product: [SQL Server](../ds_microsoft_sql_server.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   3    |     1      |      7      |    7    |

| Event Type       | Rules                                                                                                                                                                                                                                                                                                                                                      | Models                                                                                                                                    |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| failed-app-login | <b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: Failed activity from a new country<br> ↳ <b>FA-OC-F</b>: First Failed activity in session from country in which organization has never had a successful activity<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity |  • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-UC</b>: Countries for user activity |