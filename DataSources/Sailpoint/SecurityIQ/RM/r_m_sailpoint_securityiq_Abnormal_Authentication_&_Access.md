Vendor: Sailpoint
=================
### Product: [SecurityIQ](../ds_sailpoint_securityiq.md)
### Use-Case: [Abnormal Authentication & Access](../../../../UseCases/uc_abnormal_authentication_&_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |     13      |   13    |

| Event Type             | Rules                                                                                                                                                                        | Models                                  |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| account-creation       | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>NEW-USER-F</b>: User with no event history                                                    |                                         |
| account-deleted        | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user                                                     |  • <b>AE-UA</b>: All activity for users |
| account-lockout        | <b>T1110 - Brute Force</b><br> ↳ <b>SEQ-UH-02</b>: Account lockout on an asset that does not belong to this user                                                             |                                         |
| account-password-reset | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user                                                     |  • <b>AE-UA</b>: All activity for users |
| member-added           | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>NEW-USER-F</b>: User with no event history |  • <b>AE-UA</b>: All activity for users |
| member-removed         | <b>T1078 - Valid Accounts</b><br> ↳ <b>DORMANT-USER</b>: Dormant User<br> ↳ <b>AE-UA-F</b>: First activity type for user                                                     |  • <b>AE-UA</b>: All activity for users |