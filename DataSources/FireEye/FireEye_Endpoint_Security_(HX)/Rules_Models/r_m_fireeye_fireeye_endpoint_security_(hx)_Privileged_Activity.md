Vendor: FireEye
===============
### Product: [FireEye Endpoint Security (HX)](../ds_fireeye_fireeye_endpoint_security_(hx).md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      4      |    4    |

| Event Type     | Rules                                                                                                             | Models |
| -------------- | ----------------------------------------------------------------------------------------------------------------- | ------ |
| file-write     | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |
| security-alert | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive     |        |