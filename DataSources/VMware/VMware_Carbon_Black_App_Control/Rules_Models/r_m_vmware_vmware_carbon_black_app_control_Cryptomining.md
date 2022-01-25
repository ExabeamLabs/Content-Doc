Vendor: VMware
==============
### Product: [VMware Carbon Black App Control](../ds_vmware_vmware_carbon_black_app_control.md)
### Use-Case: [Cryptomining](../../../../UseCases/uc_cryptomining.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |     16      |   16    |

| Event Type                    | Rules                                                                                                                | Models |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------ |
| network-connection-failed     | <b>T1496 - Resource Hijacking</b><br> ↳ <b>A-NET-Coin-IP</b>: Connection to IP associated with cryptocurrency mining |        |
| network-connection-successful | <b>T1496 - Resource Hijacking</b><br> ↳ <b>A-NET-Coin-IP</b>: Connection to IP associated with cryptocurrency mining |        |
| process-created               | <b>T1496 - Resource Hijacking</b><br> ↳ <b>EPA-Shadow-Mining-name</b>: Process ending with 'miner.exe' has been run  |        |