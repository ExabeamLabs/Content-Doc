Vendor: StealthBits
===================
### Product: [StealthIntercept](../ds_stealthbits_stealthintercept.md)
### Use-Case: [Disabled Account Activity](../../../../UseCases/uc_disabled_account_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      9      |    9    |

| Event Type             | Rules                                                                                                             | Models |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- | ------ |
| file-permission-change | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |
| file-read              | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |
| file-write             | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |