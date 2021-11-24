Vendor: Sangfor
===============
### Product: [NGAF](../ds_sangfor_ngaf.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      3      |    3    |

| Event Type           | Rules                                                                                                                                                                                                                                                                        | Models |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UI-Ransomware</b>: User attempted to connect to IP address which is associated to Ransomware<br> ↳ <b>WEB-UD-Ransomware</b>: User attempted to connect to domain which is associated to Ransomware |        |
| web-activity-denied  | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UI-Ransomware</b>: User attempted to connect to IP address which is associated to Ransomware<br> ↳ <b>WEB-UD-Ransomware</b>: User attempted to connect to domain which is associated to Ransomware |        |