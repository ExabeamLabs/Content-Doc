Vendor: Vormetric
=================
### Product: [Vormetric](../ds_vormetric_vormetric.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      2      |    2    |

| Event Type | Rules                                                                                                                                                                                                                                        | Models                                   |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| file-alert | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                            |                                          |
| file-read  | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-PRIV</b>: Non-Privileged user accessed privileged folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |  • <b>FA-FT-PRIV</b>: Privileged Folders |