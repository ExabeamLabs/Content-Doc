Vendor: Namespace rDirectory
============================
### Product: [Namespace rDirectory](../ds_namespace_rdirectory_namespace_rdirectory.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      7      |    7    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                              | Models                                                              |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| ds-access  | <b>T1003.006 - OS Credential Dumping: DCSync</b><br> ↳ <b>A-DCSync</b>: Possible DCSync Attack: New domain controller detected<br> ↳ <b>DCSync-ExistHost</b>: Possible DCSync attack - existing host has replicated Active Directory.<br> ↳ <b>DCSync-FirstDS</b>: Possible DCSync attack - first DS access event from host.<br><br><b>T1207 - Rogue Domain Controller</b><br> ↳ <b>A-DS-DCShadow</b>: Possible DCShadow attack by asset detected. |  • <b>DS-HOSTS</b>: Models hosts in an Active Directory environment |