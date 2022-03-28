Vendor: Honeywell
=================
### Product: [Honeywell Pro-Watch](../ds_honeywell_honeywell_pro-watch.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   2    |     1      |      2      |    2    |

| Event Type       | Rules    | Models    |
| ---- | ---- | ---- |
| account-creation | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>NEW-USER-F</b>: User with no event history    |    |
| physical-access  | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>PA-VPN-02</b>: Badge access after VPN login |  • <b>PA-VPN-02</b>: Users who accessed a physical location after vpn login<br> • <b>AE-UA</b>: All activity for users |