Vendor: VMware
==============
### Product: [Carbon Black EDR](../ds_vmware_carbon_black_edr.md)
### Use-Case: [Cryptomining](../../../../UseCases/uc_cryptomining.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   0    |     2      |     11      |   11    |

| Event Type    | Rules    | Models |
| ---- | ---- | ------ |
| network-connection-successful | <b>T1496 - Resource Hijacking</b><br> ↳ <b>A-NET-Coin-IP</b>: Connection to IP associated with cryptocurrency mining    |        |
| process-created    | <b>T1496 - Resource Hijacking</b><br> ↳ <b>A-EPA-Shadow-Mining-name</b>: Process ending with 'miner.exe' has been run on this asset<br> ↳ <b>EPA-Shadow-Mining-name</b>: Process ending with 'miner.exe' has been run    |        |
| web-activity-denied    | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-Shadow-Mining-IP</b>: User has connected to a known coinmining/shadowmining IP<br><br><b>T1496 - Resource Hijacking</b><br> ↳ <b>A-NET-Coin-IP</b>: Connection to IP associated with cryptocurrency mining<br> ↳ <b>A-WEB-Shadow-Mining</b>: Host has browsed to a known coinmining/shadowmining domain<br> ↳ <b>WEB-Shadow-Mining-IP</b>: User has connected to a known coinmining/shadowmining IP |        |