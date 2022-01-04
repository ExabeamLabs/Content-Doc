Vendor: Symantec
================
### Product: [Symantec Critical System Protection](../ds_symantec_symantec_critical_system_protection.md)
### Use-Case: [Brute Force Attack](../../../../UseCases/uc_brute_force_attack.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   0    |     2      |      6      |    6    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Models |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| failed-logon | <b>T1110 - Brute Force</b><br> ↳ <b>A-FL-MULTI-USERS-L</b>: Multiple users failed to login (L)<br> ↳ <b>A-FL-MULTI-USERS-M</b>: Multiple users failed to login (M)<br> ↳ <b>A-FL-MULTI-DEST-M</b>: Failed logins to multiple destinations from host (M)<br> ↳ <b>SEQ-UH-08</b>: Abnormal number of failed logons for this user<br> ↳ <b>SEQ-UH-14</b>: Failed logon due to bad credentials<br><br><b>T1110.003 - T1110.003</b><br> ↳ <b>A-FL-MULTI-USERS-SRC</b>: The same host failed to login to multiple users |        |