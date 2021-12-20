Vendor: VMS Software
====================
### Product: [OpenVMS](../ds_vms_software_openvms.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   0    |     2      |      5      |    5    |

| Event Type          | Rules                                                                                                                                                                   | Models |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                           |        |
| batch-logon         | <b>T1078.002 - T1078.002</b><br> ↳ <b>SL-UH-F</b>: First access from asset for a service account<br> ↳ <b>SL-UH-A</b>: Abnormal access from asset for a service account |        |
| failed-logon        | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account           |        |
| file-delete         | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                       |        |
| file-read           | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                       |        |