Vendor: Symantec
================
### Product: [Symantec Critical System Protection](../ds_symantec_symantec_critical_system_protection.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   3    |     3      |      6      |    6    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                         | Models                                                                                                      |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| failed-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account                                                                                                                                                                                                                 |  • <b>AE-UA</b>: All activity for users                                                                     |
| local-logon  | <b>T1078.002 - T1078.002</b><br> ↳ <b>SL-UH-I</b>: Interactive logon using a service account<br> ↳ <b>SL-UH-F</b>: First access from asset for a service account<br> ↳ <b>SL-UH-A</b>: Abnormal access from asset for a service account<br><br><b>T1558 - Steal or Forge Kerberos Tickets</b><br> ↳ <b>EXPERT-PENTEST-DOMAINS</b>: Possible credentials theft attack detected |  • <b>AL-UsH</b>: Source hosts per User<br> • <b>IL-UH-SA</b>: Interactive logon hosts for service accounts |