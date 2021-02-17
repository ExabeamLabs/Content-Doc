Vendor: Alert Logic
===================
### Product: [Alert Logic](../ds_alert_logic_alert_logic.md)
### Use-Case: [Ransomware Detection](../../../../UseCases/uc_ransomware_detection.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     1      |      1      |    1    |

| Event Type    | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Models                                                                                   |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| network-alert | <b>T1204 - User Execution</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First execution of this process from a temporary directory on this asset<br> ↳ <b>EPA-TEMP-DIRECTORY-A</b>: Abnormal execution of this process from a temporary directory<br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br> ↳ <b>DEF-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session |