Vendor: Fidelis
===============
### Product: [Fidelis Network](../ds_fidelis_fidelis_network.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     2      |      2      |    2    |

| Event Type             | Rules                                                                                                                                                                                                          | Models |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| failed-logon           | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-12</b>: Logon attempt on a disabled account<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |        |
| failed-physical-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>FPA-DU</b>: Failed badge access by disabled user                                                                                                                        |        |