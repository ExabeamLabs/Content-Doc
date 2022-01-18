Vendor: Cisco
=============
### Product: [Duo Access Security](../ds_cisco_duo_access_security.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   1    |     3      |      7      |    7    |

| Event Type   | Rules                                                                                                                                                                                                          | Models                                                          |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                  |                                                                 |
| failed-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-12</b>: Logon attempt on a disabled account<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |                                                                 |
| file-delete  | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                              |                                                                 |
| vpn-login    | <b>T1133 - External Remote Services</b><br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>VPN31</b>: VPN connection using a disabled account                                                           |                                                                 |
| vpn-logout   | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user                                                                                                    |  • <b>WPA-UACount</b>: Count of admin privilege events for user |