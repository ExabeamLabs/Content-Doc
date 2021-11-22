Vendor: McAfee
==============
### Product: [McAfee Solidifier](../ds_mcafee_mcafee_solidifier.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |      1      |    1    |

| Event Type  | Rules                                                                                                                                                                                | Models                                                                                      |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| local-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user |  • <b>DC18</b>: Secondary accounts<br> • <b>AS-PV-OA</b>: Password retrieval based accounts |