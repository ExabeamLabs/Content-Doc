Vendor: Microsoft
=================
### Product: [Windows](../ds_microsoft_windows.md)
### Use-Case: [Brute Force Attack](../../../../UseCases/uc_brute_force_attack.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   1    |     3      |     58      |   58    |

| Event Type      | Rules    | Models    |
| ---- | ---- | ---- |
| account-lockout | <b>T1110 - Brute Force</b><br> ↳ <b>SEQ-UH-02</b>: Account lockout on an asset that does not belong to this user    |    |
| failed-logon    | <b>T1021.001 - Remote Services: Remote Desktop Protocol</b><br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user<br><br><b>T1110 - Brute Force</b><br> ↳ <b>A-FL-MULTI-USERS-S</b>: Multiple users failed to login (S)<br> ↳ <b>A-FL-MULTI-USERS-L</b>: Multiple users failed to login (L)<br> ↳ <b>A-FL-MULTI-USERS-M</b>: Multiple users failed to login (M)<br> ↳ <b>A-FL-MULTI-DEST-S</b>: Failed logins to multiple destinations from host (S)<br> ↳ <b>A-FL-MULTI-DEST-M</b>: Failed logins to multiple destinations from host (M)<br> ↳ <b>SEQ-UH-08</b>: Abnormal number of failed logons for this user<br> ↳ <b>SEQ-UH-14</b>: Failed logon due to bad credentials<br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user<br><br><b>T1110.003 - T1110.003</b><br> ↳ <b>A-FL-MULTI-USERS-SRC</b>: The same host failed to login to multiple users |    |
| vpn-logout      | <b>T1110 - Brute Force</b><br> ↳ <b>AUTH-F-COUNT</b>: Abnormal number of failed authentications for user    |  • <b>AUTH-F-COUNT</b>: Count of failed authentication events in a session |