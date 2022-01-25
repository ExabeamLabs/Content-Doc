Vendor: Accellion
=================
### Product: [Kiteworks](../ds_accellion_kiteworks.md)
### Use-Case: [Abnormal User Activity](../../../../UseCases/uc_abnormal_user_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   3    |     3      |      5      |    5    |

| Event Type              | Rules                                                                                                                                                                                                                        | Models                                                                                     |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| account-lockout         | <b>T1110 - Brute Force</b><br> ↳ <b>SEQ-UH-01</b>: Account lockout on an asset that belongs to this user<br> ↳ <b>SEQ-UH-02</b>: Account lockout on an asset that does not belong to this user                               |                                                                                            |
| account-password-change | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user                                                                                                                                             |  • <b>AE-UA</b>: All activity for users                                                    |
| account-unlocked        | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user                                                                                                                                             |  • <b>AE-UA</b>: All activity for users                                                    |
| failed-app-login        | <b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: Failed activity from a new country<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity |  • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-UC</b>: Countries for user activity |