Vendor: Tanium
==============
### Product: [Integrity Monitor](../ds_tanium_integrity_monitor.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      3      |    3    |

| Event Type | Rules                                                                                                                                                                                                                                      | Models                                  |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- |
| file-write | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |  • <b>FA-FT-EXEC</b>: Executive Folders |