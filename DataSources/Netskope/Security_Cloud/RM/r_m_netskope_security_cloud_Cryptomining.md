Vendor: Netskope
================
### Product: [Security Cloud](../ds_netskope_security_cloud.md)
### Use-Case: [Cryptomining](../../../../UseCases/uc_cryptomining.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   2   |   0    |         2          |      2      |    2    |

| Event Type    | Rules    | Models |
| ---- | ---- | ------ |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-Shadow-Mining</b>: User has browsed to a known coinmining/shadowmining domain<br><br><b>T1496 - Resource Hijacking</b><br> ↳ <b>A-WEB-Shadow-Mining</b>: Host has browsed to a known coinmining/shadowmining domain<br> ↳ <b>WEB-Shadow-Mining</b>: User has browsed to a known coinmining/shadowmining domain |        |
| web-activity-denied  | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-Shadow-Mining</b>: User has browsed to a known coinmining/shadowmining domain<br><br><b>T1496 - Resource Hijacking</b><br> ↳ <b>A-WEB-Shadow-Mining</b>: Host has browsed to a known coinmining/shadowmining domain<br> ↳ <b>WEB-Shadow-Mining</b>: User has browsed to a known coinmining/shadowmining domain |        |