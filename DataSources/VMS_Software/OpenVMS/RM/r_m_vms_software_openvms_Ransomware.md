Vendor: VMS Software
====================
### Product: [OpenVMS](../ds_vms_software_openvms.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      5      |    5    |

| Event Type          | Rules                                                                                                                                    | Models |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |        |
| failed-logon        | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |        |