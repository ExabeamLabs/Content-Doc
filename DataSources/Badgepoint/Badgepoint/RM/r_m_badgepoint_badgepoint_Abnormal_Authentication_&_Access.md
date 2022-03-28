Vendor: Badgepoint
==================
### Product: [Badgepoint](../ds_badgepoint_badgepoint.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   5    |     2      |      2      |    2    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| authentication-failed | <b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: Failed activity from a new country<br> ↳ <b>FA-OC-F</b>: First Failed activity in session from country in which organization has never had a successful activity<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity |  • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-UC</b>: Countries for user activity |
| physical-access       | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>PA-VPN-02</b>: Badge access after VPN login    |  • <b>PA-VPN-02</b>: Users who accessed a physical location after vpn login<br> • <b>AE-UA</b>: All activity for users    |