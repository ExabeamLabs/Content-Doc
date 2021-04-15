Vendor: AWS
===========
### Product: [AWS CloudTrail](../ds_aws_aws_cloudtrail.md)
### Use-Case: [Disabled Account Abuse](../../../../UseCases/uc_disabled_account_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      2      |    2    |

| Event Type          | Rules                                                                                                         | Models |
| ------------------- | ------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity        | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account |        |
| app-activity-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account |        |