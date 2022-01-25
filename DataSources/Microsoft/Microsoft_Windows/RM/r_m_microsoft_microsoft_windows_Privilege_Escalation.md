Vendor: Microsoft
=================
### Product: [Microsoft Windows](../ds_microsoft_microsoft_windows.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  22   |   14   |     8      |     22      |   22    |

| Event Type        | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| account-switch    | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>DC18-New</b>: New account switch to privileged account<br><br><b>T1098 - Account Manipulation</b><br> ↳ <b>AS-PV-UsH-F</b>: First password retrieval from asset for user<br><br><b>T1003 - OS Credential Dumping</b><br> ↳ <b>AS-PV-UT-A</b>: Abnormal user Password retrieval activity time<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>AS-UA-A</b>: Abnormal switch to target account for user<br> ↳ <b>AS-UA-F-PRIV</b>: Account switch to a privileged or executive account<br> ↳ <b>AS-UA-FS</b>: First account switch for user<br> ↳ <b>AS-PV-OU-F</b>: First password retrieval activity for user in organization<br> ↳ <b>AS-PV-OG-F</b>: First password retrieval activity for user in peer group<br> ↳ <b>AS-PV-US-F</b>: First password retrieval using this safe value for user<br> ↳ <b>AS-PV-US-A</b>: Abnormal password retrieval using this safe value for user |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session<br> • <b>DC18</b>: Secondary accounts<br> • <b>AS-PV-UsH</b>: Source Hosts using password retrieval accounts for user<br> • <b>AS-PV-UT-TOW</b>: Password retrieval activity time for user<br> • <b>AS-PV-US</b>: Safe values for user<br> • <b>AS-PV-OG</b>: Password retrieval activity for users in the peer group<br> • <b>AS-PV-OU</b>: Password retrieval activity for users in the organization<br> • <b>AS-UA</b>: Target credentials for user |
| dlp-alert         | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| local-logon       | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |  • <b>DC18</b>: Secondary accounts<br> • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session<br> • <b>AS-PV-OA</b>: Password retrieval based accounts                                                                                                                                                                                                                                                                                                                                                         |
| network-alert     | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| privileged-access | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| remote-access     | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |  • <b>DC18</b>: Secondary accounts<br> • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session<br> • <b>AS-PV-OA</b>: Password retrieval based accounts                                                                                                                                                                                                                                                                                                                                                         |
| remote-logon      | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |  • <b>DC18</b>: Secondary accounts<br> • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session<br> • <b>AS-PV-OA</b>: Password retrieval based accounts                                                                                                                                                                                                                                                                                                                                                         |
| security-alert    | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| share-access      | <b>T1484 - Group Policy Modification</b><br> ↳ <b>SA-Bloodhound-Main-1</b>: Possible Bloodhound Tool Usage by this user accessing srcsvc folder.<br> ↳ <b>SA-Bloodhound-Main-2</b>: Possible Bloodhound Tool Usage by this user accessing lsarpc folder.<br><br><b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>SA-Bloodhound-2</b>: ADMIN IPC Share samr folder accessed<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>SA-Bloodhound-2</b>: ADMIN IPC Share samr folder accessed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| vpn-logout        | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user.<br><br><b>T1003 - OS Credential Dumping</b><br> ↳ <b>AS-PV-USCOUNT-A</b>: Abnormal number of password safes used by user<br> ↳ <b>AS-PV-OSize-A</b>: Abnormal number of password retrievals in the organization<br> ↳ <b>AS-PV-GSize-A</b>: Abnormal number of password retrievals in the peer group<br> ↳ <b>AS-PV-USize-A</b>: Abnormal number of password retrievals in the user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user.<br> • <b>AS-PV-USize</b>: Count of password retrievals in a session for the user<br> • <b>AS-PV-GSize</b>: Count of password retrievals in a session for the peer group<br> • <b>AS-PV-OSize</b>: Count of password retrievals in a session for the organization<br> • <b>AS-PV-USCOUNT</b>: Count of safe values accessed in a session                                                                                                                     |