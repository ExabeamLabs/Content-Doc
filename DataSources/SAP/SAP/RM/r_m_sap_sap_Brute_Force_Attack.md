Vendor: SAP
===========
### Product: [SAP](../ds_sap_sap.md)
### Use-Case: [Brute Force Attack](../../../../UseCases/uc_brute_force_attack.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |     10      |   10    |

| Event Type       | Rules                                                                                                                              | Models                                                |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| account-creation | <b>T1110 - Brute Force</b><br> ↳ <b>A-ACCT-CR-DEL</b>: Account created and deleted on asset                                        |                                                       |
| account-deleted  | <b>T1110 - Brute Force</b><br> ↳ <b>A-ACCT-CR-DEL</b>: Account created and deleted on asset                                        |                                                       |
| account-lockout  | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-01</b>: Account lockout on an asset that belongs to this user                        |                                                       |
| remote-logon     | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user |  • <b>AS-PV-OA</b>: Password retrieval based accounts |