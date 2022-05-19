Vendor: Thycotic Secret Server
==============================
### Product: [Thycotic Secret Server](../ds_thycotic_secret_server_thycotic_secret_server.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  10   |   6    |     2      |      4      |    4    |

| Event Type     | Rules    | Models    |
| ---- | ---- | ---- |
| account-switch | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-UA-A</b>: Abnormal switch to target account for user<br> ↳ <b>AS-UA-F-PRIV</b>: Account switch to a privileged or executive account<br> ↳ <b>AS-UA-FS</b>: First account switch for user<br> ↳ <b>DC18-New</b>: New account switch to privileged account<br><br><b>T1555.005 - T1555.005</b><br> ↳ <b>AS-PV-OU-F</b>: First password retrieval activity for user in organization<br> ↳ <b>AS-PV-OG-F</b>: First password retrieval activity for user in peer group<br> ↳ <b>AS-PV-US-F</b>: First password retrieval using this safe value for user<br> ↳ <b>AS-PV-US-A</b>: Abnormal password retrieval using this safe value for user<br> ↳ <b>AS-PV-UT-A</b>: Abnormal user Password retrieval activity time<br> ↳ <b>AS-PV-UsH-F</b>: First password retrieval from asset for user |  • <b>AS-PV-UsH</b>: Source Hosts using password retrieval accounts for user<br> • <b>AS-PV-UT-TOW</b>: Password retrieval activity time for user<br> • <b>AS-PV-US</b>: Safe values for user<br> • <b>AS-PV-OG</b>: Password retrieval activity for users in the peer group<br> • <b>AS-PV-OU</b>: Password retrieval activity for users in the organization<br> • <b>AS-UA</b>: Target credentials for user |