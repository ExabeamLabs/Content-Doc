Vendor: Trend Micro
===================
### Product: [Deep Security Agent](../ds_trend_micro_deep_security_agent.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      3      |    3    |

| Event Type               | Rules                                                                                                                                                    | Models                                                                                       |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| privileged-object-access | <b>T1059.003 - T1059.003</b><br> ↳ <b>WPA-OH-F</b>: First execution of critical windows command using privileged access on this host in the organization |  • <b>WPA-OH</b>: Assets on which critical windows commands are executed in the organization |
| security-alert           | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                            |                                                                                              |