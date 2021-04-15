Vendor: Zeek
============
### Product: [Zeek Network Security Monitor](../ds_zeek_zeek_network_security_monitor.md)
### Use-Case: [Service Account Abuse](../../../../UseCases/uc_service_account_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     1      |     24      |   24    |

| Event Type   | Rules                                                                                                                                                         | Models                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| app-activity | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-SA-NC</b>: New service account access to application                                                             |                                         |
| failed-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account |  • <b>AE-UA</b>: All activity for users |