Vendor: BlackBerry
==================
### Product: [BlackBerry Protect](../ds_blackberry_blackberry_protect.md)
### Use-Case: [Disabled Account Abuse](../../../../UseCases/uc_disabled_account_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      6      |    6    |

| Event Type   | Rules                                                                                                             | Models |
| ------------ | ----------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account     |        |
| app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account     |        |
| file-alert   | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |