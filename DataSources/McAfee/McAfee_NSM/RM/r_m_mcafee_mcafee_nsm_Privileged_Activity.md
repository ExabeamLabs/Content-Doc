Vendor: McAfee
==============
### Product: [McAfee NSM](../ds_mcafee_mcafee_nsm.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      3      |    3    |

| Event Type  | Rules                                                                                                             | Models |
| ----------- | ----------------------------------------------------------------------------------------------------------------- | ------ |
| app-login   | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account     |        |
| file-delete | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |