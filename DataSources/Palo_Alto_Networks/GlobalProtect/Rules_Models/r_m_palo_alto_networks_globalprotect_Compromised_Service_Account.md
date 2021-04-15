Vendor: Palo Alto Networks
==========================
### Product: [GlobalProtect](../ds_palo_alto_networks_globalprotect.md)
### Use-Case: [Compromised Service Account](../../../../UseCases/uc_compromised_service_account.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     1      |      8      |    8    |

| Event Type   | Rules                                                                                                                                                         | Models                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| app-activity | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-SA-NC</b>: New service account access to application                                                             |                                         |
| failed-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account |  • <b>AE-UA</b>: All activity for users |