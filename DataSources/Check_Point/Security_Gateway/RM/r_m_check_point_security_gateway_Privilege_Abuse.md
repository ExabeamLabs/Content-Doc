Vendor: Check Point
===================
### Product: [Security Gateway](../ds_check_point_security_gateway.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   1    |     3      |      5      |    5    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                           | Models                                                                              |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| vpn-login  | <b>T1133 - External Remote Services</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account<br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>VPN31</b>: VPN connection using a disabled account<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>DC20a</b>: High-privilege user used during session |                                                                                     |
| vpn-logout | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user.                                                                                                                                                                                   |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user. |