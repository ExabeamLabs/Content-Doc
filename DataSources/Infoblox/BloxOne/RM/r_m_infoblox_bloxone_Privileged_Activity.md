Vendor: Infoblox
================
### Product: [BloxOne](../ds_infoblox_bloxone.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     3      |      7      |    7    |

| Event Type                 | Rules                                                                                                                                                       | Models |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-login                  | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                               |        |
| dlp-email-alert-out-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                               |        |
| process-created            | <b>T1059 - Command and Scripting Interperter</b><br> ↳ <b>EPA-OH-CS</b>: First execution of critical windows command on a Domain Controller/Critical System |        |
| security-alert             | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                               |        |