Vendor: Microsoft
=================
### Product: [Sysmon](../ds_microsoft_sysmon.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      7      |    7    |

| Event Type  | Rules                                                                                                             | Models |
| ----------- | ----------------------------------------------------------------------------------------------------------------- | ------ |
| file-delete | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |
| file-write  | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |