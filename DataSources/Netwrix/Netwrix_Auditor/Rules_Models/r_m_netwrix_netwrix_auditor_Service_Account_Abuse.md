Vendor: Netwrix
===============
### Product: [Netwrix Auditor](../ds_netwrix_netwrix_auditor.md)
### Use-Case: [Service Account Abuse](../../../../UseCases/uc_service_account_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     1      |     15      |   15    |

| Event Type   | Rules                                                                                                                                                         | Models                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| app-activity | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-SA-NC</b>: New service account access to application                                                             |                                         |
| app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-SA-NC</b>: New service account access to application                                                             |                                         |
| failed-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account |  • <b>AE-UA</b>: All activity for users |