Vendor: Cisco
=============
### Product: [Cisco Secure Network Analytics](../ds_cisco_cisco_secure_network_analytics.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  13   |   2    |     2      |      1      |    1    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| vpn-logout | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-UHcount-S</b>: Abnormal number of logon assets (S)<br> ↳ <b>AL-UHcount-M</b>: Abnormal number of logon assets (M)<br> ↳ <b>AL-UHcount-L</b>: Abnormal number of logon assets (L)<br> ↳ <b>AL-OHcount</b>: Abnormal number of logged on assets compared to the organization<br> ↳ <b>AL-GHcount</b>: Abnormal number of logged on assets compared to group<br> ↳ <b>RA-UHcount-S</b>: Abnormal number of accessed hosts for user (S)<br> ↳ <b>RA-UHcount-M</b>: Abnormal number of accessed hosts for user (M)<br> ↳ <b>RA-UHcount-L</b>: Abnormal number of accessed hosts for user (L)<br> ↳ <b>RA-OHcount</b>: Abnormal number of accessed hosts for the organization<br> ↳ <b>RA-GHcount</b>: Abnormal number of accessed assets for group<br> ↳ <b>DC08d-new</b>: Abnormal number of assets compared to group for a new user<br> ↳ <b>DC14g-new</b>: Abnormal number of accessed assets for group of new user<br> ↳ <b>DC17j-new</b>: Abnormal number of accessed zones for group of a new user<br><br><b>T1021 - Remote Services</b><br> ↳ <b>RA-UHcount-S</b>: Abnormal number of accessed hosts for user (S)<br> ↳ <b>RA-UHcount-M</b>: Abnormal number of accessed hosts for user (M)<br> ↳ <b>RA-UHcount-L</b>: Abnormal number of accessed hosts for user (L)<br> ↳ <b>RA-OHcount</b>: Abnormal number of accessed hosts for the organization<br> ↳ <b>RA-GHcount</b>: Abnormal number of accessed assets for group |  • <b>RA-OHcount</b>: Count of assets access per user in the organization<br> • <b>AL-OHcount</b>: Count of assets logon per user in the organization |