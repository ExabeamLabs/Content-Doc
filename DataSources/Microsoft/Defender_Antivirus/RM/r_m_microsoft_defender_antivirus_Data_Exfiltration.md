Vendor: Microsoft
=================
### Product: [Defender Antivirus](../ds_microsoft_defender_antivirus.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      1      |    1    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| file-alert | <b>TA0002 - TA0002</b><br> ↳ <b>FA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during file activity<br> ↳ <b>FA-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user during file activity |  • <b>FA-UP-TEMP</b>: Process executable TEMP directories for this user during file activity |