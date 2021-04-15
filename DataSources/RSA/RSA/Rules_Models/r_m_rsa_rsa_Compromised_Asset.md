Vendor: RSA
===========
### Product: [RSA](../ds_rsa_rsa.md)
### Use-Case: [Compromised Asset](../../../../UseCases/uc_compromised_asset.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      1      |    1    |

| Event Type         | Rules                                                                                                                              | Models                                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| netflow-connection | <b>T1046 - Network Service Scanning</b><br> ↳ <b>NETFLOW-OsH-SweepScan-A</b>: Abnormal for asset to access 20 assets in 10 seconds |  • <b>A-NETFLOW-OsH-Scanners</b>: Assets that access multiple assets within seconds in the organization |