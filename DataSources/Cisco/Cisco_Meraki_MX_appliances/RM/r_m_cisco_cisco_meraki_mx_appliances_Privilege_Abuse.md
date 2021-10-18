Vendor: Cisco
=============
### Product: [Cisco Meraki MX appliances](../ds_cisco_cisco_meraki_mx_appliances.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      7      |    7    |

| Event Type | Rules                                                                                                                                                         | Models                                                                              |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| vpn-login  | <b>T1133 - External Remote Services</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account                                                    |                                                                                     |
| vpn-logout | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user. |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user. |