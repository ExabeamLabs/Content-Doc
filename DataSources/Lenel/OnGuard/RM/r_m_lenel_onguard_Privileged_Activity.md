Vendor: Lenel
=============
### Product: [OnGuard](../ds_lenel_onguard.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      2      |    2    |

| Event Type             | Rules                                                                                                         | Models |
| ---------------------- | ------------------------------------------------------------------------------------------------------------- | ------ |
| failed-physical-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>FPA-DU</b>: Failed badge access by disabled user                       |        |
| physical-access        | <b>T1078 - Valid Accounts</b><br> ↳ <b>PA-DU</b>: Badge access by disabled user                               |        |
| security-alert         | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |        |