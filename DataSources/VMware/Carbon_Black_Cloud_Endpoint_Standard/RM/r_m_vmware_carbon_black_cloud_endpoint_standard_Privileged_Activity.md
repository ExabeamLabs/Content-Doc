Vendor: VMware
==============
### Product: [Carbon Black Cloud Endpoint Standard](../ds_vmware_carbon_black_cloud_endpoint_standard.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   1    |     4      |     10      |   10    |

| Event Type       | Rules                                                                                                                                                                                                                                      | Models                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- |
| app-login        | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                                              |                                         |
| failed-app-login | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                                              |                                         |
| file-write       | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |  • <b>FA-FT-EXEC</b>: Executive Folders |
| process-created  | <b>T1059 - Command and Scripting Interperter</b><br> ↳ <b>EPA-OH-CS</b>: First execution of critical windows command on a Domain Controller/Critical System                                                                                |                                         |
| security-alert   | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                                                                                                              |                                         |