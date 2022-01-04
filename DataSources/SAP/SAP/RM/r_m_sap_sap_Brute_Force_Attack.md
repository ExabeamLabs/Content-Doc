Vendor: SAP
===========
### Product: [SAP](../ds_sap_sap.md)
### Use-Case: [Brute Force Attack](../../../../UseCases/uc_brute_force_attack.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |     10      |   10    |

| Event Type       | Rules                                                                                                            | Models |
| ---------------- | ---------------------------------------------------------------------------------------------------------------- | ------ |
| account-creation | <b>T1110 - Brute Force</b><br> ↳ <b>A-ACCT-CR-DEL</b>: Account created and deleted on asset                      |        |
| account-deleted  | <b>T1110 - Brute Force</b><br> ↳ <b>A-ACCT-CR-DEL</b>: Account created and deleted on asset                      |        |
| account-lockout  | <b>T1110 - Brute Force</b><br> ↳ <b>SEQ-UH-02</b>: Account lockout on an asset that does not belong to this user |        |