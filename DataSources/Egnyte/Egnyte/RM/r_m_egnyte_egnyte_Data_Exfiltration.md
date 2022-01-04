Vendor: Egnyte
==============
### Product: [Egnyte](../ds_egnyte_egnyte.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      8      |    8    |

| Event Type | Rules                                                                                                                                                                                                                                    | Models                                                                                       |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| file-write | <b>TA0002 - TA0002</b><br> ↳ <b>FA-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user during file activity<br> ↳ <b>Suspicious-LNK</b>: A suspicious .lnk file used, possible ATP activity |  • <b>FA-UP-TEMP</b>: Process executable TEMP directories for this user during file activity |