Vendor: Cisco
=============
### Product: [Cisco Adaptive Security Appliance](../ds_cisco_cisco_adaptive_security_appliance.md)
### Use-Case: [Cryptomining](../../../../UseCases/uc_cryptomining.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |     13      |   13    |

| Event Type                    | Rules                                                                                                                                                                                                                                                                                                                                                                    | Models |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| network-connection-successful | <b>T1496 - Resource Hijacking</b><br> ↳ <b>A-NET-Coin-IP</b>: Connection to IP associated with cryptocurrency mining                                                                                                                                                                                                                                                     |        |
| process-created               | <b>T1496 - Resource Hijacking</b><br> ↳ <b>EPA-Shadow-Mining-name</b>: Process ending with 'miner.exe' has been run                                                                                                                                                                                                                                                      |        |
| web-activity-denied           | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1496 - Resource Hijacking</b><br> ↳ <b>A-NET-Coin-IP</b>: Connection to IP associated with cryptocurrency mining<br> ↳ <b>A-WEB-Shadow-Mining</b>: Host has browsed to a known coinmining/shadowmining domain<br> ↳ <b>WEB-Shadow-Mining</b>: User has browsed to a known coinmining/shadowmining domain |        |