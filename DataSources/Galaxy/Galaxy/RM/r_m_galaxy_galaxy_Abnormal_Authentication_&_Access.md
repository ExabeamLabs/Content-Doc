Vendor: Galaxy
==============
### Product: [Galaxy](../ds_galaxy_galaxy.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   2    |     2      |      2      |    2    |

| Event Type      | Rules                                                                                                                                                                                                                                                                | Models                                                                                                                 |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| physical-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>DC23</b>: Abnormal session start time<br> ↳ <b>DC24</b>: Abnormal day of week<br> ↳ <b>PA-VPN-02</b>: Badge access after VPN login |  • <b>PA-VPN-02</b>: Users who accessed a physical location after vpn login<br> • <b>AE-UA</b>: All activity for users |
| print-activity  | <b>T1110 - Brute Force</b><br> ↳ <b>PR-SRC-CODE</b>: Printed document with source code file extension<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User                                                                                   |                                                                                                                        |