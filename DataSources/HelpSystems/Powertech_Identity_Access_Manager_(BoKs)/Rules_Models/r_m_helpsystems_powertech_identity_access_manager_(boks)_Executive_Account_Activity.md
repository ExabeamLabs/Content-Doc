Vendor: HelpSystems
===================
### Product: [Powertech Identity Access Manager (BoKs)](../ds_helpsystems_powertech_identity_access_manager_(boks).md)
### Use-Case: [Executive Account Activity](../../../../UseCases/uc_executive_account_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      7      |    7    |

| Event Type   | Rules                                                                                                                                                                                                             | Models                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| local-logon  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset                                                                                                                      |  • <b>AL-HT-EXEC</b>: Executive Assets |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |  • <b>AL-HT-EXEC</b>: Executive Assets |