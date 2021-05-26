Vendor: VMware
==============
### Product: [VMware Carbon Black Cloud Endpoint Standard](../ds_vmware_vmware_carbon_black_cloud_endpoint_standard.md)
### Use-Case: [Cryptomining](../../../../UseCases/uc_cryptomining.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      6      |    6    |

| Event Type                    | Rules                                                                                                                | Models |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------ |
| network-connection-successful | <b>T1496 - Resource Hijacking</b><br> ↳ <b>A-NET-Coin-IP</b>: Connection to IP associated with cryptocurrency mining |        |
| process-created               | <b>T1496 - Resource Hijacking</b><br> ↳ <b>EPA-Shadow-Mining-name</b>: Process ending with 'miner.exe' has been run  |        |