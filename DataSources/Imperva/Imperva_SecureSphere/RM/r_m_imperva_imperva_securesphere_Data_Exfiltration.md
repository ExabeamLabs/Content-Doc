Vendor: Imperva
===============
### Product: [Imperva SecureSphere](../ds_imperva_imperva_securesphere.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   2   |   1    |         1          |      1      |    1    |

| Event Type     | Rules    | Models    |
| ---- | ---- | ---- |
| database-alert | <b>TA0002 - TA0002</b><br> ↳ <b>DB-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during database activity<br> ↳ <b>DB-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user during database activity |  • <b>DB-UP-TEMP</b>: Process executable TEMP directories for this user during database activity |