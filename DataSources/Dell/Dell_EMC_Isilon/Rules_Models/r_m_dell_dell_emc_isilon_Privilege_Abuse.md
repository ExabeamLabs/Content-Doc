Vendor: Dell
============
### Product: [Dell EMC Isilon](../ds_dell_dell_emc_isilon.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |      4      |    4    |

| Event Type    | Rules                                                                                                                                                                                                                     | Models                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| file-delete   | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                         |                                        |
| file-read     | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                         |                                        |
| file-write    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                         |                                        |
| remote-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1021 - Remote Services</b><b>T1078 - Valid Accounts</b><br> ↳ <b>RA-HT-EXEC-new</b>: New user remote access to executive asset |  • <b>AL-HT-EXEC</b>: Executive Assets |