Vendor: Cisco
=============
### Product: [Cisco Secure Network Analytics](../ds_cisco_cisco_secure_network_analytics.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  12   |   4    |     3      |      1      |    1    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| vpn-logout | <b>T1110 - Brute Force</b><br> ↳ <b>APP-UFL-COUNT</b>: Abnormal number of failed application logins for user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>AL-UHcount-S</b>: Abnormal number of logon assets (S)<br> ↳ <b>AL-UHcount-M</b>: Abnormal number of logon assets (M)<br> ↳ <b>AL-UHcount-L</b>: Abnormal number of logon assets (L)<br> ↳ <b>AL-OHcount</b>: Abnormal number of logged on assets compared to the organization<br> ↳ <b>AL-GHcount</b>: Abnormal number of logged on assets compared to group<br> ↳ <b>VPN-End-DUR</b>: Abnormal VPN session duration<br> ↳ <b>DC08d-new</b>: Abnormal number of assets compared to group for a new user<br> ↳ <b>DC14g-new</b>: Abnormal number of accessed assets for group of new user<br> ↳ <b>DC17j-new</b>: Abnormal number of accessed zones for group of a new user<br> ↳ <b>APP-UAgC-F</b>: First activity from country and first os/browser/user agent for user in same session<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>VPN-BSum</b>: Abnormal amount of data uploaded during VPN Session<br> ↳ <b>VPN-End-DUR</b>: Abnormal VPN session duration |  • <b>APP-UFL-COUNT</b>: Count of failed application logins in a session<br> • <b>VPN-End-DUR</b>: VPN session duration<br> • <b>VPN-BSum</b>: Sum of bytes uploaded during VPN<br> • <b>AL-OHcount</b>: Count of assets logon per user in the organization |