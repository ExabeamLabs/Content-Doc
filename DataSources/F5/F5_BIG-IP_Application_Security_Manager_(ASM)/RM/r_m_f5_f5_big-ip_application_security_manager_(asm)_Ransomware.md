Vendor: F5
==========
### Product: [F5 BIG-IP Application Security Manager (ASM)](../ds_f5_f5_big-ip_application_security_manager_(asm).md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      3      |    3    |

| Event Type           | Rules                                                                                                                                                                                                                                                                                                                         | Models |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| web-activity-allowed | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>WEB-UD-Ransomware</b>: User attempted to connect to domain which is associated to Ransomware<br><br><b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UI-Ransomware</b>: User attempted to connect to IP address which is associated to Ransomware |        |
| web-activity-denied  | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>WEB-UD-Ransomware</b>: User attempted to connect to domain which is associated to Ransomware<br><br><b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UI-Ransomware</b>: User attempted to connect to IP address which is associated to Ransomware |        |