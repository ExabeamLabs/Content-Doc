Vendor: Fortinet
================
### Product: [Fortinet VPN](../ds_fortinet_fortinet_vpn.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   2    |     4      |      3      |    3    |

| Event Type          | Rules    | Models    |
| ---- | ---- | ---- |
| vpn-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account<br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>VPN31</b>: VPN connection using a disabled account<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account<br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>VPN31</b>: VPN connection using a disabled account |    |
| vpn-logout          | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user.<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user    |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user.<br> • <b>WPA-UACount</b>: Count of admin privilege events for user |
| web-activity-denied | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity    |    |