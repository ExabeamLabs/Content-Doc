Vendor: Quest Software
======================
### Product: [Change Auditor](../ds_quest_software_change_auditor.md)
### Use-Case: [Credential Theft](../../../../UseCases/uc_credential_theft.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     3      |      3      |    3    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                                              | Models                                                              |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| ds-access    | <b>T1558 - Steal or Forge Kerberos Tickets</b><br> ↳ <b>ATP-AS-REP-2</b>: Suspicious UAC directory service change indicating AS-REP Roasting<br><br><b>T1003.006 - OS Credential Dumping: DCSync</b><br> ↳ <b>DCSync-ExistHost</b>: Possible DCSync attack - existing host has replicated Active Directory.<br> ↳ <b>DCSync-FirstDS</b>: Possible DCSync attack - first DS access event from host. |  • <b>DS-HOSTS</b>: Models hosts in an Active Directory environment |
| failed-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-14</b>: Failed logon due to bad credentials                                                                                                                                                                                                                                                                                                          |                                                                     |