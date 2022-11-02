Vendor: Citrix
==============
### Product: [Citrix Netscaler](../ds_citrix_citrix_netscaler.md)
### Use-Case: [Data Access](../../../../UseCases/uc_data_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   8   |   5    |     3      |      5      |    5    |

| Event Type      | Rules    | Models    |
| ---- | ---- | ---- |
| app-login       | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-UApp-F</b>: First login or activity within an application for user<br> ↳ <b>APP-UApp-A</b>: Abnormal login or activity within an application for user<br> ↳ <b>APP-AppU-F</b>: First login to an application for a user with no history<br> ↳ <b>APP-AppG-F</b>: First login to an application for group<br> ↳ <b>APP-GApp-A</b>: Abnormal login to an application for group |  • <b>APP-GApp</b>: Group Logons to Applications<br> • <b>APP-AppG</b>: Groups per Application<br> • <b>APP-AppU</b>: User Logons to Applications<br> • <b>APP-UApp</b>: Applications per User |
| process-created | <b>T1003 - OS Credential Dumping</b><br> ↳ <b>A-CP-Sensitive-Files</b>: Copying sensitive files with credential data on this asset<br> ↳ <b>CP-Sensitive-Files</b>: Copying sensitive files with credential data    |    |
| vpn-logout      | <b>T1110 - Brute Force</b><br> ↳ <b>APP-UFL-COUNT</b>: Abnormal number of failed application logins for user    |  • <b>APP-UFL-COUNT</b>: Count of failed application logins in a session    |