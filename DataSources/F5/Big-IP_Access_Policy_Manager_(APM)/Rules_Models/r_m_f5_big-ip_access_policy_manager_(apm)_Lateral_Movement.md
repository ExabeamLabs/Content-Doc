Vendor: F5
==========
### Product: [Big-IP Access Policy Manager (APM)](../ds_f5_big-ip_access_policy_manager_(apm).md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      2      |    2    |

| Event Type                | Rules                                                                                                                              | Models                              |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| authentication-failed     | <b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: Failed activity from a new country                                   |  • <b>UA-UC</b>: Countries for user |
| authentication-successful | <b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user |  • <b>UA-UC</b>: Countries for user |