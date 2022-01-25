Vendor: Tanium
==============
### Product: [Integrity Monitor](../ds_tanium_integrity_monitor.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      3      |    3    |

| Event Type | Rules                                                                                                                                                                                                                                           | Models                                                                                       |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| file-write | <b>T1204 - User Execution</b><br> ↳ <b>FA-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user during file activity<br> ↳ <b>Suspicious-LNK</b>: A suspicious .lnk file used, possible ATP activity |  • <b>FA-UP-TEMP</b>: Process executable TEMP directories for this user during file activity |