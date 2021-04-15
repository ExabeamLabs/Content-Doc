Vendor: Fast Enterprises
========================
### Product: [Fast Enterprises GenTax](../ds_fast_enterprises_fast_enterprises_gentax.md)
### Use-Case: [Internal Fraud](../../../../UseCases/uc_internal_fraud.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   3    |     1      |      1      |    1    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                               | Models                                                                                                                                     |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| app-login  | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-UApp-F</b>: First login or activity within an application for user<br> ↳ <b>APP-UApp-A</b>: Abnormal login or activity within an application for user<br> ↳ <b>APP-AppU-F</b>: First login to an application for a user with no history<br> ↳ <b>APP-AppG-F</b>: First login to an application for group |  • <b>APP-AppG</b>: Groups per Application<br> • <b>APP-AppU</b>: User Logons to Applications<br> • <b>APP-UApp</b>: Applications per User |