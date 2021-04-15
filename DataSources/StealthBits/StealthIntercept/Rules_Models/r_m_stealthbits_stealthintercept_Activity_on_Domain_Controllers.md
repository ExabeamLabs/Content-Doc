Vendor: StealthBits
===================
### Product: [StealthIntercept](../ds_stealthbits_stealthintercept.md)
### Use-Case: [Activity on Domain Controllers](../../../../UseCases/uc_activity_on_domain_controllers.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      9      |    9    |

| Event Type | Rules                                                                                                                                                                                                                                          | Models                                                              |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| ds-access  | <b>T1003.006 - OS Credential Dumping: DCSync</b><br> ↳ <b>DCSync-ExistHost</b>: Possible DCSync attack - existing host has replicated Active Directory.<br> ↳ <b>DCSync-FirstDS</b>: Possible DCSync attack - first DS access event from host. |  • <b>DS-HOSTS</b>: Models hosts in an Active Directory environment |