Vendor: Varonis
===============
### Product: [Data Security Platform](../ds_varonis_data_security_platform.md)
### Use-Case: [Disabled Account Abuse](../../../../UseCases/uc_disabled_account_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      5      |    5    |

| Event Type             | Rules                                                                                                             | Models |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- | ------ |
| file-delete            | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |
| file-permission-change | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |
| file-read              | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |
| file-write             | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |