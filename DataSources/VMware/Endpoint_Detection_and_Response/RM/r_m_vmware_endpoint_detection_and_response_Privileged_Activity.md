Vendor: VMware
==============
### Product: [Endpoint Detection and Response](../ds_vmware_endpoint_detection_and_response.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   1    |     5      |      5      |    5    |

| Event Type          | Rules                                                                                                                                                                                                                                                                                                         | Models                                  |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| file-read           | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                    |  • <b>FA-FT-EXEC</b>: Executive Folders |
| file-write          | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                    |  • <b>FA-FT-EXEC</b>: Executive Folders |
| process-created     | <b>T1059 - Command and Scripting Interperter</b><br> ↳ <b>EPA-OH-CS</b>: First execution of critical windows command on a Domain Controller/Critical System                                                                                                                                                   |                                         |
| web-activity-denied | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller<br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller |                                         |