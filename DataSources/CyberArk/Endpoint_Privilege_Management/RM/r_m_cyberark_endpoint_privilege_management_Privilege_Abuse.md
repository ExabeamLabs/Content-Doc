Vendor: CyberArk
================
### Product: [Endpoint Privilege Management](../ds_cyberark_endpoint_privilege_management.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   5   |   5    |         1          |      1      |    1    |

| Event Type        | Rules    | Models    |
| ---- | ---- | ---- |
| privileged-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-OU-F</b>: First privileged access event for user for organization<br> ↳ <b>WPA-OG-F</b>: First privileged access event for user for peer group<br> ↳ <b>WPA-UH-F</b>: First privileged access event on host for user<br> ↳ <b>WPA-HZ-F</b>: First privileged access event on host from zone<br> ↳ <b>WPA-USH-F</b>: First privileged access event on source host for user |  • <b>WPA-USH</b>: Source hosts with privileged access events for user<br> • <b>WPA-HZ</b>: Source zones with privileged access events for host<br> • <b>WPA-UH</b>: Hosts with privileged access events for user<br> • <b>WPA-OG</b>: Privileged access activity for users in the peer group<br> • <b>WPA-OU</b>: Privileged access activity for users in the organization |