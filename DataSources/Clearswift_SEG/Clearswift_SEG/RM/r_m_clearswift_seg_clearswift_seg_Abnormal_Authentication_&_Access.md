Vendor: Clearswift SEG
======================
### Product: [Clearswift SEG](../ds_clearswift_seg_clearswift_seg.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     1      |      4      |    4    |

| Event Type      | Rules                                                                                                                                                                         | Models                                                                                                                 |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| physical-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>PA-VPN-02</b>: Badge access after VPN login |  • <b>PA-VPN-02</b>: Users who accessed a physical location after vpn login<br> • <b>AE-UA</b>: All activity for users |