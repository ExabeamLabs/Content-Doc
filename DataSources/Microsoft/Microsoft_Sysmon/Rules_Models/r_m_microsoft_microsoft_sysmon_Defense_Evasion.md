Vendor: Microsoft
=================
### Product: [Microsoft Sysmon](../ds_microsoft_microsoft_sysmon.md)
### Use-Case: [Defense Evasion](../../../../UseCases/uc_defense_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      6      |    6    |

| Event Type      | Rules                                                                                                                                                                                                                                                                            | Models                                                                        |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| process-created | <b>T1093 - T1093</b><br> ↳ <b>PC-ParentName-W3WP-F</b>: First time child process creation for Exchange web front-end process w3wp.exe<br> ↳ <b>PC-ParentName-UMWorkerProcess-F</b>: First time child process creation for Exchange Unified Messaging service UMWorkerProcess.exe |  • <b>A-PC-ParentName-ProcessName</b>: Processes for parent parent processes. |