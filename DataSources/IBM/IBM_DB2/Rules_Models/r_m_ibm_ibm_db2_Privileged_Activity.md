Vendor: IBM
===========
### Product: [IBM DB2](../ds_ibm_ibm_db2.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      4      |    4    |

| Event Type     | Rules                                                                                                                                                                           | Models                                       |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| remote-logon   | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive<br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| security-alert | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                                                   |                                              |