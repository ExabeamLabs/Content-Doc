Vendor: Cisco
=============
### Product: [Cisco ISE](../ds_cisco_cisco_ise.md)
### Use-Case: [Brute Force Attack](../../../../UseCases/uc_brute_force_attack.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |     12      |   12    |

| Event Type      | Rules    | Models    |
| ---- | ---- | ---- |
| account-lockout | <b>T1110 - Brute Force</b><br> ↳ <b>SEQ-UH-02</b>: Account lockout on an asset that does not belong to this user |    |
| vpn-logout      | <b>T1110 - Brute Force</b><br> ↳ <b>AUTH-F-COUNT</b>: Abnormal number of failed authentications for user         |  • <b>AUTH-F-COUNT</b>: Count of failed authentication events in a session |