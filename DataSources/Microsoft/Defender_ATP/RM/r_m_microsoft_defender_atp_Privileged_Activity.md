Vendor: Microsoft
=================
### Product: [Defender ATP](../ds_microsoft_defender_atp.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      2      |    2    |

| Event Type      | Rules                                                                                                                                                       | Models |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created | <b>T1059 - Command and Scripting Interperter</b><br> ↳ <b>EPA-OH-CS</b>: First execution of critical windows command on a Domain Controller/Critical System |        |
| security-alert  | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                               |        |