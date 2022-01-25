Vendor: Bitdefender
===================
### Product: [Bitdefender GravityZone](../ds_bitdefender_bitdefender_gravityzone.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   0    |     9      |      3      |    3    |

| Event Type                | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Models |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| authentication-successful | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |        |
| process-created           | <b>T1055 - Process Injection</b><br> ↳ <b>A-WannaCry</b>: Artifacts seen by WannaCry malware have been observed on this asset<br> ↳ <b>WannaCry</b>: Artifacts seen by WannaCry malware have been observed<br><br><b>T1070.004 - Indicator Removal on Host: File Deletion</b><br> ↳ <b>A-Sus-GUP-Usage</b>: Execution of the Notepad++ updater in a suspicious directory on this asset.<br> ↳ <b>Fsutil-Sus-Invocation</b>: Suspicious parameters of fsutil were detected.<br><br><b>T1003 - OS Credential Dumping</b><br> ↳ <b>A-CP-Sensitive-Files</b>: Copying sensitive files with credential data on this asset<br> ↳ <b>CP-Sensitive-Files</b>: Copying sensitive files with credential data<br><br><b>T1070 - Indicator Removal on Host</b><br> ↳ <b>A-CP-Sensitive-Files</b>: Copying sensitive files with credential data on this asset<br> ↳ <b>CP-Sensitive-Files</b>: Copying sensitive files with credential data<br><br><b>T1218.011 - Signed Binary Proxy Execution: Rundll32</b><br> ↳ <b>A-CP-Sensitive-Files</b>: Copying sensitive files with credential data on this asset<br> ↳ <b>CP-Sensitive-Files</b>: Copying sensitive files with credential data<br><br><b>T1490 - Inhibit System Recovery</b><br> ↳ <b>EPA-EXPERT-SHADOW-COPIES</b>: A Suspicious command that deletes shadow copies has been executed for process<br> ↳ <b>EPA-EXPERT-DISABLE-RECOVERY</b>: A Suspicious command that disables recovery mode has been executed for process |        |
| web-activity-denied       | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UI-Ransomware</b>: User attempted to connect to IP address which is associated to Ransomware<br><br><b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-WEB-DynamicDNS</b>: Asset attempted access to a domain generated using Dynamic DNS service                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |        |