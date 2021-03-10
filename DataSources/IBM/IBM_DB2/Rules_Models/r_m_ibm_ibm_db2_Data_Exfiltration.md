Vendor: IBM
===========
### Product: [IBM DB2](../ds_ibm_ibm_db2.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |      4      |    4    |

| Event Type | Rules                                                                                                                                                                           | Models                                                                                           |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| file-read  | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user |  • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-FG</b>: Folder access by groups |