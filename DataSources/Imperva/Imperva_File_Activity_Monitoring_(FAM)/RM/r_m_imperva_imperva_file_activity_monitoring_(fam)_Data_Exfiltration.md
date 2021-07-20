Vendor: Imperva
===============
### Product: [Imperva File Activity Monitoring (FAM)](../ds_imperva_imperva_file_activity_monitoring_(fam).md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      4      |    4    |

| Event Type | Rules                                                                                                                                                                                                                                                                                               | Models                                                                                       |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| file-write | <b>T1204 - User Execution</b><br> ↳ <b>FA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during file activity<br> ↳ <b>FA-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user during file activity |  • <b>FA-UP-TEMP</b>: Process executable TEMP directories for this user during file activity |