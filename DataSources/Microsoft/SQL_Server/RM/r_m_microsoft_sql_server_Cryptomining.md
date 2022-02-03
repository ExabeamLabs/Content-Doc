Vendor: Microsoft
=================
### Product: [SQL Server](../ds_microsoft_sql_server.md)
### Use-Case: [Cryptomining](../../../../UseCases/uc_cryptomining.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     2      |      7      |    7    |

| Event Type          | Rules    | Models |
| ---- | ---- | ------ |
| web-activity-denied | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-Shadow-Mining-IP</b>: User has connected to a known coinmining/shadowmining IP<br><br><b>T1496 - Resource Hijacking</b><br> ↳ <b>A-NET-Coin-IP</b>: Connection to IP associated with cryptocurrency mining<br> ↳ <b>A-WEB-Shadow-Mining</b>: Host has browsed to a known coinmining/shadowmining domain<br> ↳ <b>WEB-Shadow-Mining-IP</b>: User has connected to a known coinmining/shadowmining IP |        |