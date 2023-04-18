Vendor: Amazon
==============
### Product: [AWS CloudTrail](../ds_amazon_aws_cloudtrail.md)
### Use-Case: [Cryptomining](../../../../UseCases/uc_cryptomining.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   1   |   1    |         2          |      1      |    1    |

| Event Type          | Rules    | Models    |
| ---- | ---- | ---- |
| aws-instance-create | <b>T1074 - Data Staged</b><br> ↳ <b>AWS-UserRunInstances-Org-F</b>: First time AWS instance creation for user<br><br><b>T1496 - Resource Hijacking</b><br> ↳ <b>AWS-UserRunInstances-Org-F</b>: First time AWS instance creation for user |  • <b>AWS-UserRunInstances-Org</b>: AWS instance creations |