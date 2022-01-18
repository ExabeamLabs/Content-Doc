Vendor: Bromium
===============
### Product: [Bromium Secure Platform](../ds_bromium_bromium_secure_platform.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     3      |      3      |    3    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Models |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| share-access | <b>T1484 - Group Policy Modification</b><br> ↳ <b>SA-Bloodhound-Main-1</b>: Possible Bloodhound Tool Usage by this user accessing srcsvc folder.<br> ↳ <b>SA-Bloodhound-Main-2</b>: Possible Bloodhound Tool Usage by this user accessing lsarpc folder.<br><br><b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>SA-Bloodhound-2</b>: ADMIN IPC Share samr folder accessed<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>SA-Bloodhound-2</b>: ADMIN IPC Share samr folder accessed |        |