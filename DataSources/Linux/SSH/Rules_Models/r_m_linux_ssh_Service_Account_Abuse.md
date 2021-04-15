Vendor: Linux
=============
### Product: [SSH](../ds_linux_ssh.md)
### Use-Case: [Service Account Abuse](../../../../UseCases/uc_service_account_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      2      |    2    |

| Event Type   | Rules                                                                                                                                                         | Models                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| failed-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account |  • <b>AE-UA</b>: All activity for users |