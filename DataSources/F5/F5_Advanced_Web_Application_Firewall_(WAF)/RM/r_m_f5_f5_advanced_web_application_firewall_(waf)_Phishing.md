Vendor: F5
==========
### Product: [F5 Advanced Web Application Firewall (WAF)](../ds_f5_f5_advanced_web_application_firewall_(waf).md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |      6      |    6    |

| Event Type          | Rules                                                                                                                                                                                                                                   | Models                                    |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| dlp-email-alert-out | <b>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol</b><br> ↳ <b>EM-OD-A</b>: Abnormal email domain for organization                                                        |  • <b>EM-OD</b>: Domains per organization |
| process-created     | <b>T1566.001 - T1566.001</b><br> ↳ <b>A-Mod-Boot-Config</b>: Boot configuration data was deleted using the bcdedit command on this asset.<br> ↳ <b>Exec-Outlook-Temp</b>: A suspicious program was executed in the Outlook temp folder. |                                           |