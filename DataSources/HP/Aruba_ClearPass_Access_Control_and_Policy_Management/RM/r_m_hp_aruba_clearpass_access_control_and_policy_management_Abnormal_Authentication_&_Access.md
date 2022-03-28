Vendor: HP
==========
### Product: [Aruba ClearPass Access Control and Policy Management](../ds_hp_aruba_clearpass_access_control_and_policy_management.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   8   |   4    |     2      |      5      |    5    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| account-password-reset | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user    |  • <b>AE-UA</b>: All activity for users    |
| nac-logon    | <b>T1021 - Remote Services</b><br> ↳ <b>NAC-OAt-F</b>: First authentication type for organization<br> ↳ <b>NAC-OAt-A</b>: Abnormal authentication type for organization<br> ↳ <b>NAC-GAt-F</b>: First authentication type for peer group<br> ↳ <b>NAC-GAt-A</b>: Abnormal authentication type for peer group<br> ↳ <b>NAC-UAt-F</b>: First authentication type for user<br> ↳ <b>NAC-UAt-A</b>: Abnormal authentication type for user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>NAC-UAt-F</b>: First authentication type for user<br> ↳ <b>NAC-UAt-A</b>: Abnormal authentication type for user |  • <b>NAC-UAt</b>: Authentication Types for user<br> • <b>NAC-GAt</b>: Authentication Types for peer group<br> • <b>NAC-OAt</b>: Authentication Types for organization<br> • <b>AE-UA</b>: All activity for users |