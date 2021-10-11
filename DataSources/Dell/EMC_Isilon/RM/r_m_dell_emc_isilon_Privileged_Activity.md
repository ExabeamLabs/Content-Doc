Vendor: Dell
============
### Product: [EMC Isilon](../ds_dell_emc_isilon.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     3      |      4      |    4    |

| Event Type    | Rules                                                                                                                                                                                                                                                                                                                                  | Models                                 |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| file-delete   | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                                                                                                                      |                                        |
| file-read     | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                                                                                                                      |                                        |
| file-write    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                                                                                                                      |                                        |
| remote-access | <b>T1021 - Remote Services</b><br> ↳ <b>RA-HT-EXEC-new</b>: New user remote access to executive asset<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>RA-HT-EXEC-new</b>: New user remote access to executive asset<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |  • <b>AL-HT-EXEC</b>: Executive Assets |