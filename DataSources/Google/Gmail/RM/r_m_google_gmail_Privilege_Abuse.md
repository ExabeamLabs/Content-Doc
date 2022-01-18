Vendor: Google
==============
### Product: [Gmail](../ds_google_gmail.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |      4      |    4    |

| Event Type                | Rules                                                                                                                                                                                                                   | Models |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| dlp-email-alert-in        | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                           |        |
| dlp-email-alert-in-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                           |        |
| dlp-email-alert-out       | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                           |        |
| vpn-login                 | <b>T1133 - External Remote Services</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account<br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>VPN31</b>: VPN connection using a disabled account |        |