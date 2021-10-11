Vendor: Dell
============
### Product: [EMC Isilon](../ds_dell_emc_isilon.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   2    |     3      |      4      |    4    |

| Event Type    | Rules                                                                                                                                                                                                                                                               | Models                                   |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| file-delete   | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-PRIV</b>: Non-Privileged user accessed privileged folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                        |  • <b>FA-FT-PRIV</b>: Privileged Folders |
| file-read     | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-PRIV</b>: Non-Privileged user accessed privileged folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                        |  • <b>FA-FT-PRIV</b>: Privileged Folders |
| file-write    | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-PRIV</b>: Non-Privileged user accessed privileged folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                        |  • <b>FA-FT-PRIV</b>: Privileged Folders |
| remote-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>RA-HT-EXEC-new</b>: New user remote access to executive asset<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1021 - Remote Services</b><br> ↳ <b>RA-HT-EXEC-new</b>: New user remote access to executive asset |  • <b>AL-HT-EXEC</b>: Executive Assets   |