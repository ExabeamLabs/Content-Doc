Vendor: Synology NAS
====================
### Product: [Synology NAS](../ds_synology_nas_synology_nas.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   0    |     3      |      1      |    1    |

| Event Type   | Rules    | Models |
| ---- | ---- | ------ |
| share-access | <b>T1484 - Group Policy Modification</b><br> ↳ <b>SA-Bloodhound-Main-1</b>: Possible Bloodhound Tool Usage by this user accessing srcsvc folder.<br> ↳ <b>SA-Bloodhound-Main-2</b>: Possible Bloodhound Tool Usage by this user accessing lsarpc folder.<br> ↳ <b>SA-Bloodhound-Main-3</b>: Possible Bloodhound Tool Usage by this user accessing samr folder.<br><br><b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>SA-Bloodhound-3</b>: ADMIN IPC Share srcsvc accessed<br> ↳ <b>SA-Bloodhound-2</b>: ADMIN IPC Share samr folder accessed<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>SA-Bloodhound-3</b>: ADMIN IPC Share srcsvc accessed<br> ↳ <b>SA-Bloodhound-2</b>: ADMIN IPC Share samr folder accessed |        |