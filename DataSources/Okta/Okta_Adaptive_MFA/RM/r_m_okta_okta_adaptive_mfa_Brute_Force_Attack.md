Vendor: Okta
============
### Product: [Okta Adaptive MFA](../ds_okta_okta_adaptive_mfa.md)
### Use-Case: [Brute Force Attack](../../../../UseCases/uc_brute_force_attack.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   0    |     2      |     12      |   12    |

| Event Type       | Rules                                                                                                                                                                                                                                                                                                                                      | Models |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| account-creation | <b>T1110 - Brute Force</b><br> ↳ <b>A-ACCT-CR-DEL</b>: Account created and deleted on asset                                                                                                                                                                                                                                                |        |
| account-lockout  | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-01</b>: Account lockout on an asset that belongs to this user                                                                                                                                                                                                                                |        |
| failed-logon     | <b>T1110 - Brute Force</b><br> ↳ <b>A-FL-MULTI-USERS-SRC</b>: The same host failed to login to multiple users<br> ↳ <b>A-FL-MULTI-USERS-L</b>: Multiple users failed to login (L)<br> ↳ <b>A-FL-MULTI-USERS-M</b>: Multiple users failed to login (M)<br> ↳ <b>A-FL-MULTI-DEST-M</b>: Failed logins to multiple destinations from host (M) |        |