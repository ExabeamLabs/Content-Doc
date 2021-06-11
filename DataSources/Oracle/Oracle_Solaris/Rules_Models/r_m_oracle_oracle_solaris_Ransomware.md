Vendor: Oracle
==============
### Product: [Oracle Solaris](../ds_oracle_oracle_solaris.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     3      |      2      |    2    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Models |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created | <b>T1047 - Windows Management Instrumentation</b><br> ↳ <b>WMI-Exec-Suspicious-Cmds</b>: WMI was executed with suspicious commands.<br><br><b>T1070.004 - Indicator Removal on Host: File Deletion</b><br> ↳ <b>A-Fsutil-Sus-Invocation</b>: Suspicious parameters of fsutil were detected on this asset.<br> ↳ <b>Fsutil-Sus-Invocation</b>: Suspicious parameters of fsutil were detected.<br><br><b>T1055 - Process Injection</b><br> ↳ <b>A-WannaCry</b>: Artifacts seen by WannaCry malware have been observed on this asset |        |