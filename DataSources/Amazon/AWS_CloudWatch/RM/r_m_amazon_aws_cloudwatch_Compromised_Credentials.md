Vendor: Amazon
==============
### Product: [AWS CloudWatch](../ds_amazon_aws_cloudwatch.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      1      |    1    |

| Event Type         | Rules    | Models    |
| ---- | ---- | ---- |
| netflow-connection | <b>T1046 - Network Service Scanning</b><br> ↳ <b>A-NETFLOW-OsH-SweepScan-A</b>: Abnormal for asset to access 20 assets in 10 seconds |  • <b>A-NETFLOW-OsH-Scanners</b>: Assets that access multiple assets within seconds in the organization |