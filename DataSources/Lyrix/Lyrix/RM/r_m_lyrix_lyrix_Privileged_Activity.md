Vendor: Lyrix
=============
### Product: [Lyrix](../ds_lyrix_lyrix.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     1      |      2      |    2    |

| Event Type      | Rules                                                                                                                                                                                                  | Models                                                   |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| app-activity    | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-AT-PRIV</b>: Non-privileged user performing privileged application activity |  • <b>APP-AT-PRIV</b>: Privileged application activities |
| physical-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>PA-DU</b>: Badge access by disabled user                                                                                                                        |                                                          |