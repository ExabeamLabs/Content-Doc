Vendor: Zoom
============
### Product: [Zoom](../ds_zoom_zoom.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     2      |      7      |    7    |

| Event Type                        | Rules                                                                                                                                                                                                                                              | Models                                                                                                                                    |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| web-meeting-updated               | <b>T1078.004 - Valid Accounts: Cloud Accounts</b><br> ↳ <b>WCA-DP</b>: Meeting updated to remove password                                                                                                                                          |                                                                                                                                           |
| webconference-operations-activity | <b>T1098 - Account Manipulation</b><br> ↳ <b>WCA-OU-F</b>: First time user performs web conference administrative activity<br> ↳ <b>WCA-OA-A</b>: Abnormal for any user in the organization to perform this web conference administrative activity |  • <b>WCA-OA</b>: Web conference admin activities in the organization<br> • <b>WCA-OU</b>: Web conference admin users in the organization |