Vendor: BeyondTrust
===================
### Product: [BeyondTrust PasswordSafe](../ds_beyondtrust_beyondtrust_passwordsafe.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   5    |     1      |      3      |    3    |

| Event Type        | Rules    | Models    |
| ---- | ---- | ---- |
| account-switch    | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-UA-F-PRIV</b>: Account switch to a privileged or executive account<br> ↳ <b>DC18-New</b>: New account switch to privileged account    |    |
| app-login         | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application    |    |
| privileged-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-OU-F</b>: First privileged access event for user for organization<br> ↳ <b>WPA-OG-F</b>: First privileged access event for user for peer group<br> ↳ <b>WPA-UH-F</b>: First privileged access event on host for user<br> ↳ <b>WPA-HZ-F</b>: First privileged access event on host from zone<br> ↳ <b>WPA-USH-F</b>: First privileged access event on source host for user |  • <b>WPA-USH</b>: Source hosts with privileged access events for user<br> • <b>WPA-HZ</b>: Source zones with privileged access events for host<br> • <b>WPA-UH</b>: Hosts with privileged access events for user<br> • <b>WPA-OG</b>: Privileged access activity for users in the peer group<br> • <b>WPA-OU</b>: Privileged access activity for users in the organization |