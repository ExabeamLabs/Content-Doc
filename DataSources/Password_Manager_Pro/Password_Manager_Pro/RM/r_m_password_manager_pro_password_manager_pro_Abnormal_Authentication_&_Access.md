Vendor: Password Manager Pro
============================
### Product: [Password Manager Pro](../ds_password_manager_pro_password_manager_pro.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   3    |     2      |      2      |    2    |

| Event Type       | Rules                                                                                                                                                                                                                                                                                             | Models                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| account-switch   | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>DC23</b>: Abnormal session start time<br> ↳ <b>DC24</b>: Abnormal day of week                                                                                   |  • <b>AE-UA</b>: All activity for users                                                   |
| failed-app-login | <b>T1133 - External Remote Services</b><br> ↳ <b>FA-OC-F</b>: First Failed activity in session from country in which organization has never had a successful activity<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity |  • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-OC</b>: Countries for organization |