Vendor: Johnson Controls
========================
### Product: [Johnson Controls P2000](../ds_johnson_controls_johnson_controls_p2000.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     1      |      5      |    5    |

| Event Type   | Rules                                                                                                                                                                             | Models                                  |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application |                                         |
| failed-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account                     |  • <b>AE-UA</b>: All activity for users |