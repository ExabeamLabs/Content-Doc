Vendor: Kaspersky
=================
### Product: [Kaspersky AV](../ds_kaspersky_kaspersky_av.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      3      |    3    |

| Event Type | Rules                                                                                                                                                           | Models                                                                                       |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| file-alert | <b>T1204 - User Execution</b><br> ↳ <b>FA-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user during file activity |  • <b>FA-UP-TEMP</b>: Process executable TEMP directories for this user during file activity |