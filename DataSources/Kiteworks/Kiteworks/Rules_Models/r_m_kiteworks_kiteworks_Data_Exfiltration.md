Vendor: Kiteworks
=================
### Product: [Kiteworks](../ds_kiteworks_kiteworks.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |     10      |   10    |

| Event Type | Rules                                                                                                                                                                                                                                                                                               | Models                                                                                       |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| file-write | <b>T1204 - User Execution</b><br> ↳ <b>FA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during file activity<br> ↳ <b>FA-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user during file activity |  • <b>FA-UP-TEMP</b>: Process executable TEMP directories for this user during file activity |