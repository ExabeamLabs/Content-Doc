Vendor: Kaspersky
=================
### Product: [Kaspersky AV](../ds_kaspersky_kaspersky_av.md)
### Use-Case: [Disabled Account Activity](../../../../UseCases/uc_disabled_account_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      2      |    2    |

| Event Type         | Rules                                                                                                             | Models |
| ------------------ | ----------------------------------------------------------------------------------------------------------------- | ------ |
| dlp-email-alert-in | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account     |        |
| file-alert         | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |