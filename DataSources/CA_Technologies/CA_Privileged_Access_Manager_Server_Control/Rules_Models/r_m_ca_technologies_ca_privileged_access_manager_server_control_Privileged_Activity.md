Vendor: CA Technologies
=======================
### Product: [CA Privileged Access Manager Server Control](../ds_ca_technologies_ca_privileged_access_manager_server_control.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   2    |     3      |      5      |    5    |

| Event Type     | Rules                                                                                                                                                                                                    | Models                                       |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| account-switch | <b>T1098 - Account Manipulation</b><br> ↳ <b>AS-PV-US-F</b>: First password retrieval using this safe value for user<br> ↳ <b>AS-PV-US-A</b>: Abnormal password retrieval using this safe value for user |  • <b>AS-PV-US</b>: Safe values for user     |
| app-login      | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-SA-NC</b>: New service account access to application                                                                                                        |                                              |
| remote-logon   | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive<br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset                          |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |