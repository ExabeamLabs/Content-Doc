Vendor: Forcepoint
==================
### Product: [Forcepoint NGFW](../ds_forcepoint_forcepoint_ngfw.md)
### Use-Case: [Data Access](../../../../UseCases/uc_data_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   4    |     1      |      3      |    3    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| app-login  | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-UApp-F</b>: First login or activity within an application for user<br> ↳ <b>APP-UApp-A</b>: Abnormal login or activity within an application for user<br> ↳ <b>APP-AppU-F</b>: First login to an application for a user with no history<br> ↳ <b>APP-AppG-F</b>: First login to an application for group<br> ↳ <b>APP-GApp-A</b>: Abnormal login to an application for group |  • <b>APP-GApp</b>: Group Logons to Applications<br> • <b>APP-AppG</b>: Groups per Application<br> • <b>APP-AppU</b>: User Logons to Applications<br> • <b>APP-UApp</b>: Applications per User |