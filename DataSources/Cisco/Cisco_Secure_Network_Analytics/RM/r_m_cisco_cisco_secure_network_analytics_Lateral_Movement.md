Vendor: Cisco
=============
### Product: [Cisco Secure Network Analytics](../ds_cisco_cisco_secure_network_analytics.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   3    |     3      |      1      |    1    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| vpn-logout | <b>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting</b><br> ↳ <b>KL-USnCOUNT-A</b>: Abnormal number of services used to obtain TGTs by user<br> ↳ <b>KL-GSnCOUNT-A</b>: Abnormal number of services used to obtain TGTs by peer group<br><br><b>T1021 - Remote Services</b><br> ↳ <b>RA-UHcount-S</b>: Abnormal number of accessed hosts for user (S)<br> ↳ <b>RA-UHcount-M</b>: Abnormal number of accessed hosts for user (M)<br> ↳ <b>RA-UHcount-L</b>: Abnormal number of accessed hosts for user (L)<br> ↳ <b>RA-OHcount</b>: Abnormal number of accessed hosts for the organization<br> ↳ <b>RA-GHcount</b>: Abnormal number of accessed assets for group<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>RA-UHcount-S</b>: Abnormal number of accessed hosts for user (S)<br> ↳ <b>RA-UHcount-M</b>: Abnormal number of accessed hosts for user (M)<br> ↳ <b>RA-UHcount-L</b>: Abnormal number of accessed hosts for user (L)<br> ↳ <b>RA-OHcount</b>: Abnormal number of accessed hosts for the organization<br> ↳ <b>RA-GHcount</b>: Abnormal number of accessed assets for group |  • <b>KL-GSnCOUNT</b>: Count of services used to obtain kerberos TGTs in a session for peer group<br> • <b>KL-USnCOUNT</b>: Count of services used to obtain kerberos TGTs in a session for user<br> • <b>RA-OHcount</b>: Count of assets access per user in the organization |