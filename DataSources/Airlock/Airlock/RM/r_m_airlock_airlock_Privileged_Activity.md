Vendor: Airlock
===============
### Product: [Airlock](../ds_airlock_airlock.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      9      |    9    |

| Event Type          | Rules                                                                                                             | Models |
| ------------------- | ----------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account     |        |
| app-login           | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account     |        |
| failed-app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account     |        |
| file-delete         | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |
| file-download       | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |
| file-upload         | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |
| file-write          | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |