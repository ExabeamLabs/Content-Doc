Vendor: Microsoft
=================
### Product: [Microsoft Office 365](../ds_microsoft_microsoft_office_365.md)
### Use-Case: [Defense Evasion](../../../../UseCases/uc_defense_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |     27      |   27    |

| Event Type      | Rules                                                                                                                                                                                                                                                                            | Models                                                                        |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| process-created | <b>T1093 - T1093</b><br> ↳ <b>PC-ParentName-W3WP-F</b>: First time child process creation for Exchange web front-end process w3wp.exe<br> ↳ <b>PC-ParentName-UMWorkerProcess-F</b>: First time child process creation for Exchange Unified Messaging service UMWorkerProcess.exe |  • <b>A-PC-ParentName-ProcessName</b>: Processes for parent parent processes. |