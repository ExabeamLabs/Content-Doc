Vendor: Rapid7
==============
### Product: [InsightVM](../ds_rapid7_insightvm.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     3      |      1      |    1    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Models |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created | <b>T1070.004 - Indicator Removal on Host: File Deletion</b><br> ↳ <b>Fsutil-Sus-Invocation</b>: Suspicious parameters of fsutil were detected.<br><br><b>T1490 - Inhibit System Recovery</b><br> ↳ <b>EPA-EXPERT-SHADOW-COPIES</b>: A Suspicious command that deletes shadow copies has been executed for process<br> ↳ <b>EPA-EXPERT-DISABLE-RECOVERY</b>: A Suspicious command that disables recovery mode has been executed for process<br><br><b>T1055 - Process Injection</b><br> ↳ <b>A-WannaCry</b>: Artifacts seen by WannaCry malware have been observed on this asset |        |