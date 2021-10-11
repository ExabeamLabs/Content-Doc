Vendor: Citrix
==============
### Product: [Citrix Netscaler VPN](../ds_citrix_citrix_netscaler_vpn.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   2    |     3      |      6      |    6    |

| Event Type    | Rules                                                                                                                                                                                                                                                                                                                                  | Models                                                          |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| remote-access | <b>T1021 - Remote Services</b><br> ↳ <b>RA-HT-EXEC-new</b>: New user remote access to executive asset<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>RA-HT-EXEC-new</b>: New user remote access to executive asset<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive |  • <b>AL-HT-EXEC</b>: Executive Assets                          |
| remote-logon  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                                                                                                      |  • <b>AL-HT-EXEC</b>: Executive Assets                          |
| vpn-logout    | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user                                                                                                                                                                                                                            |  • <b>WPA-UACount</b>: Count of admin privilege events for user |