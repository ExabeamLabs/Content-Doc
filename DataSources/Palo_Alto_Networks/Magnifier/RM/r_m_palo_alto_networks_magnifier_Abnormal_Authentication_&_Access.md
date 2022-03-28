Vendor: Palo Alto Networks
==========================
### Product: [Magnifier](../ds_palo_alto_networks_magnifier.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   3    |     2      |      1      |    1    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| remote-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>RA-GH-A</b>: Abnormal access to asset for group<br> ↳ <b>RA-GH-F</b>: First access to asset for group<br> ↳ <b>RA-UH-A</b>: Abnormal access to asset<br> ↳ <b>RA-UH-F</b>: First access to asset<br> ↳ <b>NEW-USER-F</b>: User with no event history<br><br><b>T1021 - Remote Services</b><br> ↳ <b>RA-GH-A</b>: Abnormal access to asset for group<br> ↳ <b>RA-GH-F</b>: First access to asset for group<br> ↳ <b>RA-UH-A</b>: Abnormal access to asset<br> ↳ <b>RA-UH-F</b>: First access to asset |  • <b>RA-UH</b>: Assets accessed by this user remotely<br> • <b>RA-GH</b>: Assets accessed by this peer group remotely<br> • <b>AE-UA</b>: All activity for users |