Vendor: SentinelOne
===================
### Product: [SentinelOne](../ds_sentinelone_sentinelone.md)
### Use-Case: [Abnormal Account Management Activity](../../../../UseCases/uc_abnormal_account_management_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |     14      |   14    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                   | Models                                                                       |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| process-created | <b>T1078 - Valid Accounts</b><b>T1098 - Account Manipulation</b><br> ↳ <b>EXE-ACTIVE-ORG-F</b>: First time net.exe has been used to disable/enable a user account by this user.<br> ↳ <b>EXE-ACTIVE-ORG-A</b>: Abnormal usage of net.exe to disable/enable a user account by this user. |  • <b>NET-EXE-ACTIVE-ORG</b>: Using net.exe to disable/enable a user account |