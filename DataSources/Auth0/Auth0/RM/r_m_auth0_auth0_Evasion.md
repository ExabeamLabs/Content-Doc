Vendor: Auth0
=============
### Product: [Auth0](../ds_auth0_auth0.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     1      |      4      |    4    |

| Event Type                    | Rules                                                                                                                                  | Models |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-login                     | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                |        |
| failed-logon                  | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP |        |
| network-connection-successful | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Aggregation</b>: Inbound connection from a known TOR IP                             |        |