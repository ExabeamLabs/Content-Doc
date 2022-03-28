Vendor: Zeek
============
### Product: [Zeek Network Security Monitor](../ds_zeek_zeek_network_security_monitor.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   2    |     7      |     23      |   23    |

| Event Type     | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity   | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>EM-InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions    |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions |
| failed-logon   | <b>T1210 - Exploitation of Remote Services</b><br> ↳ <b>A-Suspicious-Zerologon</b>: Failed authentication attempt on this asset.    |    |
| kerberos-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1555.005 - T1555.005</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user    |  • <b>AS-PV-OA</b>: Password retrieval based accounts    |
| ntlm-logon     | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1555.005 - T1555.005</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user    |  • <b>AS-PV-OA</b>: Password retrieval based accounts    |
| remote-logon   | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1555.005 - T1555.005</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user    |  • <b>AS-PV-OA</b>: Password retrieval based accounts    |
| share-access   | <b>T1484 - Group Policy Modification</b><br> ↳ <b>SA-Bloodhound-Main-1</b>: Possible Bloodhound Tool Usage by this user accessing srcsvc folder.<br> ↳ <b>SA-Bloodhound-Main-2</b>: Possible Bloodhound Tool Usage by this user accessing lsarpc folder.<br> ↳ <b>SA-Bloodhound-Main-3</b>: Possible Bloodhound Tool Usage by this user accessing samr folder.<br><br><b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>SA-Bloodhound-3</b>: ADMIN IPC Share srcsvc accessed<br> ↳ <b>SA-Bloodhound-2</b>: ADMIN IPC Share samr folder accessed<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>SA-Bloodhound-3</b>: ADMIN IPC Share srcsvc accessed<br> ↳ <b>SA-Bloodhound-2</b>: ADMIN IPC Share samr folder accessed |    |