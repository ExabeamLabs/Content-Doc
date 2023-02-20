Vendor: Salesforce
==================
### Product: [Salesforce](../ds_salesforce_salesforce.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  13   |   8    |         3          |      2      |    2    |

| Event Type     | Rules    | Models    |
| ---- | ---- | ---- |
| account-switch | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-UA-A</b>: Abnormal switch to target account for user<br> ↳ <b>AS-UA-F-PRIV</b>: Account switch to a privileged or executive account<br> ↳ <b>AS-UA-FS</b>: First account switch for user<br> ↳ <b>DC18-New</b>: New account switch to privileged account<br><br><b>T1555.005 - T1555.005</b><br> ↳ <b>AS-PV-OU-F</b>: First password retrieval activity for user in organization<br> ↳ <b>AS-PV-OG-F</b>: First password retrieval activity for user in peer group<br> ↳ <b>AS-PV-US-F</b>: First password retrieval using this safe value for user<br> ↳ <b>AS-PV-US-A</b>: Abnormal password retrieval using this safe value for user<br> ↳ <b>AS-PV-UT-A</b>: Abnormal user Password retrieval activity time<br> ↳ <b>AS-PV-UsH-F</b>: First password retrieval from asset for user |  • <b>AS-PV-UsH</b>: Source Hosts using password retrieval accounts for user<br> • <b>AS-PV-UT-TOW</b>: Password retrieval activity time for user<br> • <b>AS-PV-US</b>: Safe values for user<br> • <b>AS-PV-OG</b>: Password retrieval activity for users in the peer group<br> • <b>AS-PV-OU</b>: Password retrieval activity for users in the organization<br> • <b>AE-UA</b>: All activity for users<br> • <b>AS-UA</b>: Target credentials for user |
| app-activity   | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>EM-InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions    |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions    |