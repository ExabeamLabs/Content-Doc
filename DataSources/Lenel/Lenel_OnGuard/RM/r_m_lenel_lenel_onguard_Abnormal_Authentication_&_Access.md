Vendor: Lenel
=============
### Product: [Lenel OnGuard](../ds_lenel_lenel_onguard.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   2    |     1      |      1      |    1    |

| Event Type             | Rules                                                                                                                                                                                                                                                                | Models                                                                                                                 |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| failed-physical-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>PA-VPN-02</b>: Badge access after VPN login                                                                                                                                                                                   |  • <b>PA-VPN-02</b>: Users who accessed a physical location after vpn login                                            |
| physical-access        | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>DC23</b>: Abnormal session start time<br> ↳ <b>DC24</b>: Abnormal day of week<br> ↳ <b>PA-VPN-02</b>: Badge access after VPN login |  • <b>PA-VPN-02</b>: Users who accessed a physical location after vpn login<br> • <b>AE-UA</b>: All activity for users |