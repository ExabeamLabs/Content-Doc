Vendor: Microsoft
=================
### Product: [Sysmon](../ds_microsoft_sysmon.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |      5      |    5    |

| Event Type  | Rules                                                                                                                                                                           | Models                                                                                           |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| file-delete | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user |  • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-FG</b>: Folder access by groups |
| file-write  | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user |  • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-FG</b>: Folder access by groups |