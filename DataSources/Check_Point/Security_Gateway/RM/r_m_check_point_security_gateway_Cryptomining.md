Vendor: Check Point
===================
### Product: [Security Gateway](../ds_check_point_security_gateway.md)
### Use-Case: [Cryptomining](../../../../UseCases/uc_cryptomining.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      4      |    4    |

| Event Type                    | Rules                                                                                                                | Models |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------ |
| network-connection-failed     | <b>T1496 - Resource Hijacking</b><br> ↳ <b>A-NET-Coin-IP</b>: Connection to IP associated with cryptocurrency mining |        |
| network-connection-successful | <b>T1496 - Resource Hijacking</b><br> ↳ <b>A-NET-Coin-IP</b>: Connection to IP associated with cryptocurrency mining |        |