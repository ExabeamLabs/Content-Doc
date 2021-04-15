Vendor: SkySea
==============
### Product: [ClientView](../ds_skysea_clientview.md)
### Use-Case: [System Account Activity](../../../../UseCases/uc_system_account_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |     15      |   15    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                   | Models                                                                 |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| process-created | <b>T1047 - Windows Management Instrumentation</b><b>T1098 - Account Manipulation</b><br> ↳ <b>EXE-RENAME-ORG-F</b>: First time WMIC.exe has been used to rename a user account by this user.<br> ↳ <b>RENAME-GRP-ORG-F</b>: First time WMIC.exe has been used to rename a group by this user.<br> ↳ <b>EXE-RENAME-ORG-A</b>: Abnormal usage of WMIC.exe to rename a group by this user. |  • <b>WMIC-EXE-RENAME-ORG</b>: Using WMIC.exe to rename a user account |