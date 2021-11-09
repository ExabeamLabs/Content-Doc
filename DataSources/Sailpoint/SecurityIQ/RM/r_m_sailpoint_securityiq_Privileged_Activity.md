Vendor: Sailpoint
=================
### Product: [SecurityIQ](../ds_sailpoint_securityiq.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |     13      |   13    |

| Event Type                | Rules                                                                                                                                                                                                                                      | Models                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- |
| dlp-email-alert-in-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                                              |                                         |
| file-delete               | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |  • <b>FA-FT-EXEC</b>: Executive Folders |
| file-download             | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                          |                                         |
| file-permission-change    | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |  • <b>FA-FT-EXEC</b>: Executive Folders |
| file-read                 | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |  • <b>FA-FT-EXEC</b>: Executive Folders |
| file-upload               | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                          |                                         |
| file-write                | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |  • <b>FA-FT-EXEC</b>: Executive Folders |