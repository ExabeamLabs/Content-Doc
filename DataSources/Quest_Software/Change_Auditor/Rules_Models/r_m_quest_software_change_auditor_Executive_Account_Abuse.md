Vendor: Quest Software
======================
### Product: [Change Auditor](../ds_quest_software_change_auditor.md)
### Use-Case: [Executive Account Abuse](../../../../UseCases/uc_executive_account_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      8      |    8    |

| Event Type   | Rules                                                                                        | Models                                 |
| ------------ | -------------------------------------------------------------------------------------------- | -------------------------------------- |
| local-logon  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset |  • <b>AL-HT-EXEC</b>: Executive Assets |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset |  • <b>AL-HT-EXEC</b>: Executive Assets |