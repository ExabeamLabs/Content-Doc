Vendor: Forcepoint
==================
### Product: [Forcepoint NGFW](../ds_forcepoint_forcepoint_ngfw.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  12   |   4    |     2      |      3      |    3    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| app-login  | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-GC-A</b>: Abnormal activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization<br> ↳ <b>UA-OC-A</b>: Abnormal activity from country for organization<br> ↳ <b>NEW-USER-F</b>: User with no event history<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-GC-new</b>: Abnormal country for group by new user<br> ↳ <b>UA-OC-new</b>: Abnormal country for organization by new user<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-F</b>: First activity from country for user<br> ↳ <b>UA-UC-A</b>: Abnormal activity from country for user<br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-GC-A</b>: Abnormal activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization<br> ↳ <b>UA-OC-A</b>: Abnormal activity from country for organization<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-GC-new</b>: Abnormal country for group by new user<br> ↳ <b>UA-OC-new</b>: Abnormal country for organization by new user |  • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-UC</b>: Countries for user activity<br> • <b>AE-UA</b>: All activity for users |