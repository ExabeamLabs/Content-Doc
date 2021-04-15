Vendor: Microsoft
=================
### Product: [Microsoft RRA](../ds_microsoft_microsoft_rra.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     2      |      2      |    2    |

| Event Type                | Rules                                                                                                                              | Models                              |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| authentication-successful | <b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user |  • <b>UA-UC</b>: Countries for user |
| vpn-login                 | <b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user |  • <b>UA-UC</b>: Countries for user |