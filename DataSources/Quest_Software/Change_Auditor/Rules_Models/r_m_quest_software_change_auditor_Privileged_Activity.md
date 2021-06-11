Vendor: Quest Software
======================
### Product: [Change Auditor](../ds_quest_software_change_auditor.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   2    |     3      |      8      |    8    |

| Event Type   | Rules                                                                                                                                                                                                                                          | Models                                                              |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| ds-access    | <b>T1003.006 - OS Credential Dumping: DCSync</b><br> ↳ <b>DCSync-ExistHost</b>: Possible DCSync attack - existing host has replicated Active Directory.<br> ↳ <b>DCSync-FirstDS</b>: Possible DCSync attack - first DS access event from host. |  • <b>DS-HOSTS</b>: Models hosts in an Active Directory environment |
| failed-logon | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                                                                                                                  |                                                                     |
| local-logon  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset                                                                                                                                                   |  • <b>AL-HT-EXEC</b>: Executive Assets                              |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                              |  • <b>AL-HT-EXEC</b>: Executive Assets                              |