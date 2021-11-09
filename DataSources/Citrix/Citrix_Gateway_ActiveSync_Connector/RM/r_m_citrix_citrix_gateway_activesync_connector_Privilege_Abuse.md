Vendor: Citrix
==============
### Product: [Citrix Gateway ActiveSync Connector](../ds_citrix_citrix_gateway_activesync_connector.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      2      |    2    |

| Event Type              | Rules                                                                                                         | Models |
| ----------------------- | ------------------------------------------------------------------------------------------------------------- | ------ |
| account-password-change | <b>T1098 - Account Manipulation</b><br> ↳ <b>AM-UA-APLocU-F</b>: First account password change for local user |        |
| app-activity-failed     | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account |        |