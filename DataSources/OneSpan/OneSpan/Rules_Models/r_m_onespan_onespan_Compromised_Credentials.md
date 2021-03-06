Vendor: OneSpan
===============
### Product: [OneSpan](../ds_onespan_onespan.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      1      |    1    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Models                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- |
| failed-logon | <b>T1212 - Exploitation for Credential Access</b><br> ↳ <b>A-Kerberos-Manipulation-Failure</b>: Possible Kerberos failure code triggered by manipulation of Kerberos messages on the asset.<br> ↳ <b>Kerberos-Manipulation-Failure</b>: Rare Kerberos failure code triggered by possible manipulation of Kerberos messages.<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account |  • <b>AE-UA</b>: All activity for users |