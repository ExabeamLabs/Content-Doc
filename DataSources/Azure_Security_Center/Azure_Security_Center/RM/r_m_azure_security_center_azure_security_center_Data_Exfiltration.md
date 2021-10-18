Vendor: Azure Security Center
=============================
### Product: [Azure Security Center](../ds_azure_security_center_azure_security_center.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      4      |    4    |

| Event Type     | Rules                                                                                                                                                                                                                                                                                                       | Models                                                                                           |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| database-alert | <b>T1204 - User Execution</b><br> ↳ <b>DB-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during database activity<br> ↳ <b>DB-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user during database activity |  • <b>DB-UP-TEMP</b>: Process executable TEMP directories for this user during database activity |