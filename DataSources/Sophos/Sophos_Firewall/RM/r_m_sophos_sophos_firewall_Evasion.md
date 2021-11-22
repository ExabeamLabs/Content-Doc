Vendor: Sophos
==============
### Product: [Sophos Firewall](../ds_sophos_sophos_firewall.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      2      |    2    |

| Event Type                    | Rules                                                                                                                   | Models |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------ |
| authentication-successful     | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP |        |
| network-connection-successful | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Aggregation</b>: Inbound connection from a known TOR IP              |        |