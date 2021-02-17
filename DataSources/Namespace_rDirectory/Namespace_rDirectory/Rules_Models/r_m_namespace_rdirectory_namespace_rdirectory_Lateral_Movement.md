Vendor: Namespace rDirectory
============================
### Product: [Namespace rDirectory](../ds_namespace_rdirectory_namespace_rdirectory.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |      7      |    7    |

| Event Type       | Rules                                                                                                                                                                                                                       | Models |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| account-creation | <b>T1136.001 - Create Account: Create: Local Account</b><br> ↳ <b>AC-DhU-system-F</b>: First account creation by system account on asset<br> ↳ <b>AC-DhU-system-A</b>: Abnormal account creation by system account on asset |        |
| ds-access        | <b>T1207 - Rogue Domain Controller</b><br> ↳ <b>DS-DCShadow</b>: Possible DCShadow attack detected                                                                                                                          |        |