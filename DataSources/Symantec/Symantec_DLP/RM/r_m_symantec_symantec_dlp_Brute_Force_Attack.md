Vendor: Symantec
================
### Product: [Symantec DLP](../ds_symantec_symantec_dlp.md)
### Use-Case: [Brute Force Attack](../../../../UseCases/uc_brute_force_attack.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     2      |     10      |   10    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                                                                             | Models |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| failed-logon | <b>T1021.001 - Remote Services: Remote Desktop Protocol</b><br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user<br><br><b>T1110 - Brute Force</b><br> ↳ <b>A-FL-MULTI-USERS-SRC</b>: The same host failed to login to multiple users<br> ↳ <b>A-FL-MULTI-DEST</b>: Failed logins to multiple destinations from host<br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user |        |