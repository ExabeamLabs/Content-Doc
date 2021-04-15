Vendor: Microsoft
=================
### Product: [Microsoft Windows](../ds_microsoft_microsoft_windows.md)
### Use-Case: [Defense Evasion](../../../../UseCases/uc_defense_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   1    |     2      |     54      |   54    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                          | Models                                                                        |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| process-created | <b>T1093 - T1093</b><br> ↳ <b>PC-ParentName-W3WP-F</b>: First time child process creation for Exchange web front-end process w3wp.exe<br> ↳ <b>PC-ParentName-UMWorkerProcess-F</b>: First time child process creation for Exchange Unified Messaging service UMWorkerProcess.exe                                                                                               |  • <b>A-PC-ParentName-ProcessName</b>: Processes for parent parent processes. |
| share-access    | <br> ↳ <b>SA-Bloodhound-Main-3</b>: Possible Bloodhound Tool Usage by this user accessing samr folder.<br><br><br><br><b>T1484 - Group Policy Modification</b><br> ↳ <b>SA-Bloodhound-Main-1</b>: Possible Bloodhound Tool Usage by this user accessing srcsvc folder.<br> ↳ <b>SA-Bloodhound-Main-2</b>: Possible Bloodhound Tool Usage by this user accessing lsarpc folder. |                                                                               |