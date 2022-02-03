Vendor: Cisco
=============
### Product: [AnyConnect](../ds_cisco_anyconnect.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     3      |      3      |    3    |

| Event Type      | Rules    | Models |
| ---- | ---- | ------ |
| process-created | <b>T1482 - Domain Trust Discovery</b><br> ↳ <b>A-Trickbot-Recon</b>: Trickbot malware domain recon activity on this asset<br> ↳ <b>Trickbot-Recon</b>: Trickbot malware domain recon activity    |        |
| vpn-login       | <b>T1078 - Valid Accounts</b><br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>VPN31</b>: VPN connection using a disabled account<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>VPN31</b>: VPN connection using a disabled account |        |