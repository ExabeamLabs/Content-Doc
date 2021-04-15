Vendor: Okta
============
### Product: [Okta Adaptive MFA](../ds_okta_okta_adaptive_mfa.md)
### Use-Case: [System Account Activity](../../../../UseCases/uc_system_account_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |     11      |   11    |

| Event Type   | Rules                                                                                                                                                                                                 | Models                                                                                                                                                                   |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| member-added | <b>T1098 - Account Manipulation</b><br> ↳ <b>GM-DhU-system-F</b>: First group management by system account on asset<br> ↳ <b>AM-DhU-system-F</b>: First account management by system account on asset |  • <b>A-AM-DhU-system</b>: System accounts performing account management activities<br> • <b>A-GM-DhU-system</b>: System accounts performing group management activities |