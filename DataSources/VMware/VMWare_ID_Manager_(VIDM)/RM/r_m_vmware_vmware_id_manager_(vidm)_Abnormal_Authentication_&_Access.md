Vendor: VMware
==============
### Product: [VMWare ID Manager (VIDM)](../ds_vmware_vmware_id_manager_(vidm).md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      1      |    1    |

| Event Type               | Rules                                                                                                                                                                                                                                                                               | Models                                  |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| privileged-object-access | <b>T1543.003 - Create or Modify System Process: Windows Service</b><br> ↳ <b>SCM-Database-Privileged-Operation</b>: Privileged operations performed by non-system user on the SCM database.<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user |  • <b>AE-UA</b>: All activity for users |