Vendor: Ping Identity
=====================
### Product: [Ping Identity](../ds_ping_identity_ping_identity.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     3      |      8      |    8    |

| Event Type                | Rules                                                                                                                                                                   | Models                                  |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| account-password-reset    | <b>T1098 - Account Manipulation</b><br> ↳ <b>AM-UA-APLocU-F</b>: First account password change for local user                                                           |                                         |
| dlp-email-alert-in-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                           |                                         |
| failed-app-login          | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                           |                                         |
| service-logon             | <b>T1078.002 - T1078.002</b><br> ↳ <b>SL-UH-F</b>: First access from asset for a service account<br> ↳ <b>SL-UH-A</b>: Abnormal access from asset for a service account |  • <b>AL-UsH</b>: Source hosts per User |