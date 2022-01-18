Vendor: Quest Software
======================
### Product: [Change Auditor](../ds_quest_software_change_auditor.md)
### Use-Case: [Brute Force Attack](../../../../UseCases/uc_brute_force_attack.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |     13      |   13    |

| Event Type      | Rules                                                                                                                              | Models                                                |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| account-lockout | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-01</b>: Account lockout on an asset that belongs to this user                        |                                                       |
| local-logon     | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user |  • <b>AS-PV-OA</b>: Password retrieval based accounts |
| remote-logon    | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user |  • <b>AS-PV-OA</b>: Password retrieval based accounts |