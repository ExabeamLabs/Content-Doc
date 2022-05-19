Vendor: Palo Alto Networks
==========================
### Product: [GlobalProtect](../ds_palo_alto_networks_globalprotect.md)
### Use-Case: [Physical Security](../../../../UseCases/uc_physical_security.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   8   |   4    |     2      |      9      |    9    |

| Event Type      | Rules    | Models    |
| ---- | ---- | ---- |
| physical-access | <b>T1078 - Valid Accounts</b><br> ↳ <b>PA-UC-F</b>: First physical access in this location for user<br> ↳ <b>PA-UC-A</b>: Abnormal physical access in this location for user<br> ↳ <b>PA-UB-A</b>: Abnormal physical access in this building for user<br> ↳ <b>PA-UTi-A</b>: Badge access at abnormal time<br> ↳ <b>PA-MC</b>: Badge access in multiple cities within a session<br> ↳ <b>PA-DU</b>: Badge access by disabled user<br> ↳ <b>PA-WU</b>: Badge access by watchlist user |  • <b>PA-UTi</b>: Badge access time<br> • <b>PA-UB</b>: Building level badge access by user<br> • <b>PA-UC</b>: City level badge access by user |
| vpn-login       | <b>T1133 - External Remote Services</b><br> ↳ <b>PA-VPN-01</b>: VPN login after badge access    |  • <b>PA-VPN-01</b>: Users who vpn-in after badge access    |