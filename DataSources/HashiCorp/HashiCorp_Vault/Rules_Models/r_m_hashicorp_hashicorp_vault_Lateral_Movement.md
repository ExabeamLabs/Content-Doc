Vendor: HashiCorp
=================
### Product: [HashiCorp Vault](../ds_hashicorp_hashicorp_vault.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   3    |     2      |      2      |    2    |

| Event Type | Rules                                                                                                                                                                                                                                                                                          | Models                                                                                                                                            |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| app-login  | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-UTi</b>: Abnormal user activity time<br> ↳ <b>APP-AppSz-F</b>: First application access from network zone<br><br><b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user |  • <b>APP-AppSz</b>: Source zones per application<br> • <b>APP-UTi</b>: Application activity time for user<br> • <b>UA-UC</b>: Countries for user |