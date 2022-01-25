Vendor: StealthBits
===================
### Product: [StealthIntercept](../ds_stealthbits_stealthintercept.md)
### Use-Case: [Abnormal User Activity](../../../../UseCases/uc_abnormal_user_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      9      |    9    |

| Event Type       | Rules                                                                                                                                | Models                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- |
| account-disabled | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user                                                     |  • <b>AE-UA</b>: All activity for users |
| account-enabled  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user                                                     |  • <b>AE-UA</b>: All activity for users |
| member-added     | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>NEW-USER-F</b>: User with no event history |  • <b>AE-UA</b>: All activity for users |
| member-removed   | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user                                                     |  • <b>AE-UA</b>: All activity for users |