Vendor: Semperis
================
### Product: [DSP](../ds_semperis_dsp.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   4   |   2    |         2          |      3      |    3    |

| Event Type       | Rules    | Models    |
| ---- | ---- | ---- |
| app-login        | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application    |    |
| ds-access        | <b>T1484 - Group Policy Modification</b><br> ↳ <b>DS-APRIV</b>: Non-Privileged user accessing privileged directory service attribute<br> ↳ <b>DS-UA</b>: First access to attribute for privileged user |  • <b>DS-UA</b>: Attributes per privileged user<br> • <b>DS-APRIV</b>: Privileged user attributes |
| failed-app-login | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account    |    |