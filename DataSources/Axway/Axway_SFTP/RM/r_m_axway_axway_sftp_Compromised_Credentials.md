Vendor: Axway
=============
### Product: [Axway SFTP](../ds_axway_axway_sftp.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     3      |      2      |    2    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                               | Models                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| remote-logon | <b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br><br><b>T1021 - Remote Services</b><br> ↳ <b>A-RLA-AA-F</b>: First asset-to-asset communication<br> ↳ <b>A-RLA-AA-A</b>: Abnormal asset-to-asset communication |  • <b>A-RLA-AA</b>: Asset to asset communication (DISABLED) |