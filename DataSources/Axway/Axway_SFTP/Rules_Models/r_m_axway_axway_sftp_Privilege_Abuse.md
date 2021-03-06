Vendor: Axway
=============
### Product: [Axway SFTP](../ds_axway_axway_sftp.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   2    |     1      |      2      |    2    |

| Event Type   | Rules                                                                                                                                                                                                            | Models                                                                                 |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| file-upload  | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                |                                                                                        |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset<br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br> ↳ <b>DC18-new</b>: Account switch by new user |  • <b>AL-HT-EXEC</b>: Executive Assets<br> • <b>AL-HT-PRIV</b>: Privilege Users Assets |