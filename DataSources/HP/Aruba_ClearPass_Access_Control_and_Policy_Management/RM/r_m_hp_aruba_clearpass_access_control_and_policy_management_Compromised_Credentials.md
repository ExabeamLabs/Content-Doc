Vendor: HP
==========
### Product: [Aruba ClearPass Access Control and Policy Management](../ds_hp_aruba_clearpass_access_control_and_policy_management.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   3    |     2      |      3      |    3    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| nac-logon  | <b>T1021 - Remote Services</b><br> ↳ <b>NAC-OAt-F</b>: First authentication type for organization<br> ↳ <b>NAC-OAt-A</b>: Abnormal authentication type for organization<br> ↳ <b>NAC-GAt-F</b>: First authentication type for peer group<br> ↳ <b>NAC-GAt-A</b>: Abnormal authentication type for peer group<br> ↳ <b>NAC-UAt-F</b>: First authentication type for user<br> ↳ <b>NAC-UAt-A</b>: Abnormal authentication type for user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>NAC-UAt-F</b>: First authentication type for user<br> ↳ <b>NAC-UAt-A</b>: Abnormal authentication type for user |  • <b>NAC-UAt</b>: Authentication Types for user<br> • <b>NAC-GAt</b>: Authentication Types for peer group<br> • <b>NAC-OAt</b>: Authentication Types for organization |