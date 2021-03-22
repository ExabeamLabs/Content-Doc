Vendor: Quest Software
======================
### Product: [Change Auditor](../ds_quest_software_change_auditor.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     4      |      3      |    3    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                             | Models |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| ds-access    | <b>T1207 - Rogue Domain Controller</b><br> ↳ <b>DS-DCShadow</b>: Possible DCShadow attack detected                                                                                                                                                                                                                                |        |
| failed-logon | <b>T1550.003 - Use Alternate Authentication Material: Pass the Ticket</b><b>T1550.004 - Use Alternate Authentication Material: Web Session Cookie</b><br> ↳ <b>KL-TfG</b>: Rare Kerberos ticket failure code<br><br><b>T1110 - Brute Force</b><br> ↳ <b>FL-MULTI-DEST-M</b>: Failed logins to multiple destinations from host (M) |        |