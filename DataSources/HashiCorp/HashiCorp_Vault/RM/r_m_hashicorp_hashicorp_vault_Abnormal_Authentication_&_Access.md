Vendor: HashiCorp
=================
### Product: [HashiCorp Vault](../ds_hashicorp_hashicorp_vault.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      2      |    2    |

| Event Type               | Rules                                                                                                                    | Models |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------ | ------ |
| account-password-reset   | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user |        |
| privileged-object-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user                                         |        |