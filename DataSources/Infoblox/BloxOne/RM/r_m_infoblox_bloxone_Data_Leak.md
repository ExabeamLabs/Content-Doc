Vendor: Infoblox
================
### Product: [BloxOne](../ds_infoblox_bloxone.md)
### Use-Case: [Data Leak](../../../../UseCases/uc_data_leak.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     1      |      6      |    6    |

| Event Type                 | Rules                                                                                                                                                                                                                                                                                                                                        | Models |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| dlp-email-alert-out-failed | <b>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol</b><br> ↳ <b>FEM-UD-R</b>: Repeated email failure to domain<br> ↳ <b>FEM-FU</b>: Emailing a previously failed attachment<br> ↳ <b>EM-BSum-5MB-Fail</b>: Failed attempt to email over 5MB of data to a personal email domain. |        |